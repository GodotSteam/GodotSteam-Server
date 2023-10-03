/////////////////////////////////////////////////
///// SILENCE STEAMWORKS WARNINGS
/////////////////////////////////////////////////
//
// Turn off MSVC-only warning about strcpy
#include <cstdint>
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#pragma warning(disable:4996)
#pragma warning(disable:4828)
#endif


/////////////////////////////////////////////////
///// HEADER INCLUDES
/////////////////////////////////////////////////
//
// Include GodotSteam Server header
#include "godotsteam_server.h"

// Include some system headers
#include "string.h"
#include "fstream"
#include "vector"

using namespace godot;


/////////////////////////////////////////////////
///// DEFINING CONSTANTS
/////////////////////////////////////////////////
//
// Define Steam API constants
#define API_CALL_INVALID 0x0
#define APP_ID_INVALID 0x0
#define AUTH_TICKET_INVALID 0
#define DEPOT_ID_INVALID 0x0
#define GAME_EXTRA_INFO_MAX 64
#define INVALID_BREAKPAD_HANDLE 0
#define STEAM_ACCOUNT_ID_MASK 0xFFFFFFFF
#define STEAM_ACCOUNT_INSTANCE_MASK 0x000FFFFF
#define STEAM_BUFFER_SIZE 255
#define STEAM_LARGE_BUFFER_SIZE 8160
#define STEAM_MAX_ERROR_MESSAGE 1024
#define STEAM_USER_CONSOLE_INSTANCE 2
#define STEAM_USER_DESKTOP_INSTANCE 1
#define STEAM_USER_WEB_INSTANCE 4
#define QUERY_PORT_ERROR 0xFFFE
#define QUERY_PORT_NOT_INITIALIZED 0xFFFF

// Define Steam Server API constants
#define FLAG_ACTIVE 0x01
#define FLAG_DEDICATED 0x04
#define FLAG_LINUX 0x08
#define FLAG_NONE 0x00
#define FLAG_PASSWORDED 0x10
#define FLAG_PRIVATE 0x20
#define FLAG_SECURE 0x02
#define QUERY_PORT_SHARED 0xffff

// Define HTTP constants
#define HTTPCOOKIE_INVALID_HANDLE 0
#define HTTPREQUEST_INVALID_HANDLE 0

// Define Inventory constants
#define INVENTORY_RESULT_INVALID -1
#define ITEM_INSTANCE_ID_INVALID 0

// Define Networking Message constants
#define NETWORKING_SEND_UNRELIABLE 0
#define NETWORKING_SEND_NO_NAGLE 1
#define NETWORKING_SEND_NO_DELAY 4
#define NETWORKING_SEND_RELIABLE 8

// Define UGC constants
#define NUM_UGC_RESULTS_PER_PAGE 50
#define DEVELOPER_METADATA_MAX 5000
#define UGC_QUERY_HANDLE_INVALID 0
#define UGC_UPDATE_HANDLE_INVALID 0


/////////////////////////////////////////////////
///// STEAM SINGLETON? STEAM SINGLETON
/////////////////////////////////////////////////
//
SteamServer *SteamServer::singleton = nullptr;


/////////////////////////////////////////////////
///// STEAM OBJECT WITH CALLBACKS
/////////////////////////////////////////////////
//
SteamServer::SteamServer():
	// Game Server callbacks ////////////////////
	callbackServerConnectFailure(this, &SteamServer::server_connect_failure),
	callbackServerConnected(this, &SteamServer::server_connected),
	callbackServerDisconnected(this, &SteamServer::server_disconnected),
	callbackClientApproved(this, &SteamServer::client_approved),
	callbackClientDenied(this, &SteamServer::client_denied),
	callbackClientKicked(this, &SteamServer::client_kick),
	callbackPolicyResponse(this, &SteamServer::policy_response),
	callbackClientGroupStatus(this, &SteamServer::client_group_status),
	callbackAssociateClan(this, &SteamServer::associate_clan),
	callbackPlayerCompat(this, &SteamServer::player_compat),

	// Game Server Stat callbacks ///////////////
	callbackStatsStored(this, &SteamServer::stats_stored),
	callbackStatsUnloaded(this, &SteamServer::stats_unloaded),

	// HTTP callbacks ///////////////////////////
	callbackHTTPRequestCompleted(this, &SteamServer::http_request_completed),
	callbackHTTPRequestDataReceived(this, &SteamServer::http_request_data_received),
	callbackHTTPRequestHeadersReceived(this, &SteamServer::http_request_headers_received),

	// Inventory callbacks //////////////////////
	callbackInventoryDefinitionUpdate(this, &SteamServer::inventory_definition_update),
	callbackInventoryFullUpdate(this, &SteamServer::inventory_full_update),
	callbackInventoryResultReady(this, &SteamServer::inventory_result_ready),

	// Networking callbacks /////////////////////
	callbackP2PSessionConnectFail(this, &SteamServer::p2p_session_connect_fail),
	callbackP2PSessionRequest(this, &SteamServer::p2p_session_request),

	// Networking Messages callbacks ////////////
	callbackNetworkMessagesSessionRequest(this, &SteamServer::network_messages_session_request),
	callbackNetworkMessagesSessionFailed(this, &SteamServer::network_messages_session_failed),

	// Networking Sockets callbacks /////////////
	callbackNetworkConnectionStatusChanged(this, &SteamServer::network_connection_status_changed),
	callbackNetworkAuthenticationStatus(this, &SteamServer::network_authentication_status),
	callbackNetworkingFakeIPResult(this, &SteamServer::fake_ip_result),

	// Networking Utils callbacks ///////////////
	callbackRelayNetworkStatus(this, &SteamServer::relay_network_status),

	// UGC callbacks ////////////////////////////
	callbackItemDownloaded(this, &SteamServer::item_downloaded),
	callbackItemInstalled(this, &SteamServer::item_installed),
	callbackUserSubscribedItemsListChanged(this, &SteamServer::user_subscribed_items_list_changed)
{
	is_init_success = false;
	singleton = this;
}


/////////////////////////////////////////////////
///// INTERNAL FUNCTIONS
/////////////////////////////////////////////////
//
// Get the Steam singleton, obviously
SteamServer *SteamServer::get_singleton(){
	return singleton;
}

// Creating a Steam ID for internal use
CSteamID SteamServer::createSteamID(uint64_t steam_id, AccountType account_type){
	CSteamID converted_steam_id;
	if(account_type < 0 || account_type >= AccountType(k_EAccountTypeMax)){
		account_type = ACCOUNT_TYPE_INDIVIDUAL;
	}
	converted_steam_id.Set(steam_id, k_EUniversePublic, EAccountType(account_type));
	return converted_steam_id;
}


/////////////////////////////////////////////////
///// MAIN FUNCTIONS
/////////////////////////////////////////////////
//
// No official notes, but should be checking if the server is secured.
bool SteamServer::isServerSecure(){
	return SteamGameServer_BSecure();
}

// Gets the server's Steam ID.
uint64_t SteamServer::getServerSteamID(){
	return SteamGameServer_GetSteamID();
}

// Initialize SteamGameServer client and interface objects, and set server properties which may not be changed.
// After calling this function, you should set any additional server parameters, and then logOnAnonymous() or logOn().
bool SteamServer::serverInit(const String& ip, int game_port, int query_port, ServerMode server_mode, const String& version_number){
	// Convert the server mode back
	EServerMode mode;
	if(server_mode == 1){
		mode = eServerModeNoAuthentication;
	}
	else if(server_mode == 2){
		mode = eServerModeAuthentication;
	}
	else{
		mode = eServerModeAuthenticationAndSecure;
	}
	uint32_t ip4 = 0;
	// Resolve address and convert it
	if(ip.is_valid_ip_address()){
		char ip_bytes[4];
		sscanf(ip.utf8().get_data(), "%hhu.%hhu.%hhu.%hhu", &ip_bytes[3], &ip_bytes[2], &ip_bytes[1], &ip_bytes[0]);
		ip4 = ip_bytes[0] | ip_bytes[1] << 8 | ip_bytes[2] << 16 | ip_bytes[3] << 24;
	}
	else{
		return false;
	}
	if(!SteamGameServer_Init(ip4, (uint16)game_port, (uint16)query_port, mode, version_number.utf8().get_data())){
		return false;
	}
	return true;
}

// Initialize SteamGameServer client and interface objects, and set server properties which may not be changed.
// After calling this function, you should set any additional server parameters, and then logOnAnonymous() or logOn().
// On success STEAM_API_INIT_RESULT_OK is returned.  Otherwise, if error_message is non-NULL, it will receive a non-localized message that explains the reason for the failure
Dictionary SteamServer::serverInitEx(const String& ip, int game_port, int query_port, ServerMode server_mode, const String& version_number){
	Dictionary server_initialize;
	char error_message[STEAM_MAX_ERROR_MESSAGE] = "IP address is invalid";
	ESteamAPIInitResult initialize_result = k_ESteamAPIInitResult_FailedGeneric;

	// Convert the server mode back
	EServerMode mode;
	if(server_mode == 1){
		mode = eServerModeNoAuthentication;
	}
	else if(server_mode == 2){
		mode = eServerModeAuthentication;
	}
	else{
		mode = eServerModeAuthenticationAndSecure;
	}
	// Resolve address and convert it
	if(ip.is_valid_ip_address()){
		char ip_bytes[4];
		sscanf(ip.utf8().get_data(), "%hhu.%hhu.%hhu.%hhu", &ip_bytes[3], &ip_bytes[2], &ip_bytes[1], &ip_bytes[0]);
		uint32_t ip4 = ip_bytes[0] | ip_bytes[1] << 8 | ip_bytes[2] << 16 | ip_bytes[3] << 24;
		initialize_result = SteamGameServer_InitEx(ip4, (uint16)game_port, (uint16)query_port, mode, version_number.utf8().get_data(), &error_message);
	}
	server_initialize["status"] = initialize_result;
	server_initialize["verbal"] = error_message;

	return server_initialize;
}

// Frees all API-related memory associated with the calling thread. This memory is released automatically by RunCallbacks so single-threaded servers do not need to call this.
void SteamServer::serverReleaseCurrentThreadMemory(){
	SteamAPI_ReleaseCurrentThreadMemory();
}

// Shut down the server connection to Steam.
void SteamServer::serverShutdown(){
	SteamGameServer_Shutdown();
}


/////////////////////////////////////////////////
///// GAME SERVER FUNCTIONS
/////////////////////////////////////////////////
//
// NOTE: The following, if set, must be set before calling LogOn; they may not be changed after.
//
// Game product identifier; currently used by the master server for version checking purposes.
void SteamServer::setProduct(const String& product){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetProduct(product.utf8().get_data());
}

// Description of the game; required field and is displayed in the Steam server browser.
void SteamServer::setGameDescription(const String& description){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetGameDescription(description.utf8().get_data());
}

// If your game is a mod, pass the string that identifies it. Default is empty meaning the app is the original game.
void SteamServer::setModDir(const String& mod_directory){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetModDir(mod_directory.utf8().get_data());
}

// Is this a dedicated server? Default is false.
void SteamServer::setDedicatedServer(bool dedicated){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetDedicatedServer(dedicated);
}

// NOTE: The following are login functions.
//
// Begin process to login to a persistent game server account. You need to register for callbacks to determine the result of this operation.
void SteamServer::logOn(const String& token){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->LogOn(token.utf8().get_data());
}

// Login to a generic, anonymous account.
void SteamServer::logOnAnonymous(){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->LogOnAnonymous();
}

// Begin process of logging game server out of Steam.
void SteamServer::logOff(){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->LogOff();
}

// Status functions.
bool SteamServer::loggedOn(){
	if(SteamGameServer() == NULL){
		return false;
	}
	return SteamGameServer()->BLoggedOn();
}

bool SteamServer::secure(){
	if(SteamGameServer() == NULL){
		return false;
	}
	return SteamGameServer()->BSecure();
}

uint64_t SteamServer::getSteamID(){
	if(SteamGameServer() == NULL){
		return 0;
	}
	CSteamID serverID = SteamGameServer()->GetSteamID();
	return serverID.ConvertToUint64();
}

// Returns true if the master server has requested a restart. Only returns true once per request.
bool SteamServer::wasRestartRequested(){
	if(SteamGameServer() == NULL){
		return false;
	}
	return SteamGameServer()->WasRestartRequested();
}

// NOTE: These are server state functions and can be changed at any time.
//
// Max player count that will be reported to server browser and client queries.
void SteamServer::setMaxPlayerCount(int players_max){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetMaxPlayerCount(players_max);
}

// Number of bots. Default is zero.
void SteamServer::setBotPlayerCount(int bots){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetBotPlayerCount(bots);
}

// Set the naem of the server as it will appear in the server browser.
void SteamServer::setServerName(const String& name){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetServerName(name.utf8().get_data());
}

// Set name of map to report in server browser.
void SteamServer::setMapName(const String& map){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetMapName(map.utf8().get_data());
}

// Let people know if your server requires a password.
void SteamServer::setPasswordProtected(bool password_protected){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetPasswordProtected(password_protected);
}

// Spectator server. Default is zero, meaning it is now used.
void SteamServer::setSpectatorPort(int port){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetSpectatorPort((uint16)port);
}

// Name of spectator server. Only used if spectator port is non-zero.
void SteamServer::setSpectatorServerName(const String& name){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetSpectatorServerName(name.utf8().get_data());
}

// Call this to clear the whole list of key/values that are sent in rule queries.
void SteamServer::clearAllKeyValues(){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->ClearAllKeyValues();
}

// Call this to add/update a key/value pair.
void SteamServer::setKeyValue(const String& key, const String& value){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetKeyValue(key.utf8().get_data(), value.utf8().get_data());
}

// Set a string defining game tags for this server; optional. Allows users to filter in matchmaking/server browser.
void SteamServer::setGameTags(const String& tags){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetGameTags(tags.utf8().get_data());
}

// Set a string defining game data for this server; optional. Allows users to filter in matchmaking/server browser.
void SteamServer::setGameData(const String& data){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetGameData(data.utf8().get_data());
}

// Region identifier; optional. Default is empty meaning 'world'.
void SteamServer::setRegion(const String& region){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetRegion(region.utf8().get_data());
}

// NOTE: These functions are player list management / authentication.
//
// Retrieve ticket to be sent to the entity who wishes to authenticate you (using BeginAuthSession API).
Dictionary SteamServer::getAuthSessionTicket(const String& identity_reference){
	// Create the dictionary to use
	Dictionary auth_ticket;
	if(SteamGameServer() != NULL){
		uint32_t id = 0;
		uint32_t ticket_size = 1024;
		PackedByteArray buffer;
		buffer.resize(ticket_size);
		// If no reference is passed, just use NULL
		// Not pretty but will work for now
		if(identity_reference  != ""){
			const SteamNetworkingIdentity identity = networking_identities[identity_reference.utf8().get_data()];
			id = SteamGameServer()->GetAuthSessionTicket(buffer.ptrw(), ticket_size, &ticket_size, &identity);
		}
		else{
			id = SteamGameServer()->GetAuthSessionTicket(buffer.ptrw(), ticket_size, &ticket_size, NULL);
		}
		// Add this data to the dictionary
		auth_ticket["id"] = id;
		auth_ticket["buffer"] = buffer;
		auth_ticket["size"] = ticket_size;
	}
	return auth_ticket;
}

// Authenticate the ticket from the entity Steam ID to be sure it is valid and isn't reused.
uint32 SteamServer::beginAuthSession(PackedByteArray ticket, int ticket_size, uint64_t steam_id){
	if(SteamGameServer() == NULL){
		return -1;
	}
	CSteamID authSteamID = createSteamID(steam_id);
	return SteamGameServer()->BeginAuthSession(ticket.ptr(), ticket_size, authSteamID);
}

// Stop tracking started by beginAuthSession; called when no longer playing game with this entity;
void SteamServer::endAuthSession(uint64_t steam_id){
	if(SteamGameServer() != NULL){
		CSteamID authSteamID = createSteamID(steam_id);
		SteamGameServer()->EndAuthSession(authSteamID);
	}
}

// Cancel auth ticket from getAuthSessionTicket; called when no longer playing game with the entity you gave the ticket to.
void SteamServer::cancelAuthTicket(uint32_t auth_ticket){
	if(SteamGameServer() != NULL){
		SteamGameServer()->CancelAuthTicket(auth_ticket);
	}
}

// After receiving a user's authentication data, and passing it to sendUserConnectAndAuthenticate, use to determine if user owns DLC
int SteamServer::userHasLicenceForApp(uint64_t steam_id, uint32 app_id){
	if(SteamGameServer() == NULL){
		return 0;
	}
	CSteamID userID = (uint64)steam_id;
	return SteamGameServer()->UserHasLicenseForApp(userID, (AppId_t)app_id);
}

// Ask if user is in specified group; results returned by GSUserGroupStatus_t.
bool SteamServer::requestUserGroupStatus(uint64_t steam_id, int group_id){
	if(SteamGameServer() == NULL){
		return false;
	}
	CSteamID userID = (uint64)steam_id;
	CSteamID clan_id = (uint64)group_id;
	return SteamGameServer()->RequestUserGroupStatus(userID, clan_id);
}

// NOTE: These are in GameSocketShare mode, where instead of ISteamGameServer creating sockets to talk to master server, it lets the game use its socket to forward messages back and forth.
//
// These are used when you've elected to multiplex the game server's UDP socket rather than having the master server updater use its own sockets.
Dictionary SteamServer::handleIncomingPacket(int packet, const String& ip, int port){
	Dictionary result;
	if(SteamGameServer() == NULL){
		return result;
	}
	PackedByteArray data;
	data.resize(packet);
	// Resolve address and convert it
	if(ip.is_valid_ip_address()){
		char ip_bytes[4];
		sscanf(ip.utf8().get_data(), "%hhu.%hhu.%hhu.%hhu", &ip_bytes[3], &ip_bytes[2], &ip_bytes[1], &ip_bytes[0]);
		uint32_t ip4 = ip_bytes[0] | ip_bytes[1] << 8 | ip_bytes[2] << 16 | ip_bytes[3] << 24;
		if(SteamGameServer()->HandleIncomingPacket(data.ptrw(), packet, ip4, (uint16)port)){
			result["data"] = data;
		}
	}
	return result;
}

// AFTER calling HandleIncomingPacket for any packets that came in that frame, call this. This gets a packet that the master server updater needs to send out on UDP. Returns 0 if there are no more packets.
Dictionary SteamServer::getNextOutgoingPacket(){
	Dictionary packet;
	if(SteamGameServer() == NULL){
		return packet;
	}
	PackedByteArray out;
	int maxOut = 16 * 1024;
	uint32 address;
	uint16 port;
	// Retrieve the packet information
	int length = SteamGameServer()->GetNextOutgoingPacket(&out, maxOut, &address, &port);
	// Place packet information in dictionary and return it
	packet["length"] = length;
	packet["out"] = out;
	packet["address"] = address;
	packet["port"] = port;
	return packet;
}

// Gets the public IP of the server according to Steam.
Dictionary SteamServer::getPublicIP(){
	Dictionary public_ip;
	if(SteamGameServer() != NULL){
		SteamIPAddress_t this_public_ip = SteamGameServer()->GetPublicIP();
		// Populate the dictionary for returning
		public_ip["ipv4"] = this_public_ip.m_unIPv4;
		public_ip["ipv6"] = this_public_ip.m_rgubIPv6;
		public_ip["type"] = this_public_ip.m_eType;
	}
	return public_ip;
}

// NOTE: These are heartbeat/advertisement functions.
//
// Call this as often as you like to tell the master server updater whether or not you want it to be active (default: off).
void SteamServer::setAdvertiseServerActive(bool active){
	if(SteamGameServer() == NULL){
		return;
	}
	SteamGameServer()->SetAdvertiseServerActive(active);
}

// Associate this game server with this clan for the purposes of computing player compatibility.
void SteamServer::associateWithClan(uint64_t clan_id){
	if(SteamGameServer() == NULL){
		return;
	}
	CSteamID group_id = (uint64)clan_id;
	SteamGameServer()->AssociateWithClan(group_id);
}

// Ask if any of the current players dont want to play with this new player - or vice versa.
void SteamServer::computeNewPlayerCompatibility(uint64_t steam_id){
	if(SteamGameServer() == NULL){
		return;
	}
	CSteamID userID = (uint64)steam_id;
	SteamGameServer()->ComputeNewPlayerCompatibility(userID);
}


/////////////////////////////////////////////////
///// GAME SERVER STATS
/////////////////////////////////////////////////
//
// Resets the unlock status of an achievement for the specified user.
bool SteamServer::clearUserAchievement(uint64_t steam_id, const String& name){
	if(SteamGameServerStats() == NULL){
		return false;
	}
	CSteamID userID = (uint64)steam_id;
	return SteamGameServerStats()->ClearUserAchievement(userID, name.utf8().get_data());
}

// Gets the unlock status of the Achievement.
Dictionary SteamServer::getUserAchievement(uint64_t steam_id, const String& name){
	// Set dictionary to fill in
	Dictionary achievement;
	if(SteamGameServerStats() == NULL){
		return achievement;
	}
	CSteamID user_id = (uint64)steam_id;
	bool unlocked = false;
	bool result = SteamGameServerStats()->GetUserAchievement(user_id, name.utf8().get_data(), &unlocked);
	// Populate the dictionary
	achievement["result"] = result;
	achievement["user"] = steam_id;
	achievement["name"] = name;
	achievement["unlocked"] = unlocked;
	return achievement;
}

// Gets the current value of the a stat for the specified user.
uint32_t SteamServer::getUserStatInt(uint64_t steam_id, const String& name){
	if(SteamGameServerStats() != NULL){
		CSteamID userID = (uint64)steam_id;
		int32 value = 0;
		if(SteamGameServerStats()->GetUserStat(userID, name.utf8().get_data(), &value)){
			return value;
		}
	}
	return 0;
}

// Gets the current value of the a stat for the specified user.
float SteamServer::getUserStatFloat(uint64_t steam_id, const String& name){
	if(SteamGameServerStats() != NULL){
		CSteamID userID = (uint64)steam_id;
		float value = 0.0;
		if(SteamGameServerStats()->GetUserStat(userID, name.utf8().get_data(), &value)){
			return value;
		}
	}
	return 0.0;
}

// Asynchronously downloads stats and achievements for the specified user from the server.
void SteamServer::requestUserStats(uint64_t steam_id){
	if(SteamGameServerStats() != NULL){
		CSteamID userID = (uint64)steam_id;
		SteamAPICall_t api_call = SteamGameServerStats()->RequestUserStats(userID);
		callResultStatReceived.Set(api_call, this, &SteamServer::stats_received);
	}
}

// Unlocks an achievement for the specified user.
bool SteamServer::setUserAchievement(uint64_t steam_id, const String& name){
	if(SteamGameServerStats() == NULL){
		return false;
	}
	CSteamID userID = (uint64)steam_id;
	return SteamGameServerStats()->SetUserAchievement(userID, name.utf8().get_data());
}

// Sets / updates the value of a given stat for the specified user.
bool SteamServer::setUserStatInt(uint64_t steam_id, const String& name, int32 stat){
	if(SteamGameServerStats() == NULL){
		return false;
	}
	CSteamID userID = (uint64)steam_id;
	return SteamGameServerStats()->SetUserStat(userID, name.utf8().get_data(), stat);
}

// Sets / updates the value of a given stat for the specified user.
bool SteamServer::setUserStatFloat(uint64_t steam_id, const String& name, float stat){
	if(SteamGameServerStats() == NULL){
		return false;
	}
	CSteamID userID = (uint64)steam_id;
	return SteamGameServerStats()->SetUserStat(userID, name.utf8().get_data(), stat);
}

// Send the changed stats and achievements data to the server for permanent storage for the specified user.
void SteamServer::storeUserStats(uint64_t steam_id){
	if(SteamGameServerStats() != NULL){
		CSteamID userID = (uint64)steam_id;
		SteamGameServerStats()->StoreUserStats(userID);
	}
}

// Updates an AVGRATE stat with new values for the specified user.
bool SteamServer::updateUserAvgRateStat(uint64_t steam_id, const String& name, float this_session, double session_length){
	if(SteamGameServerStats() == NULL){
		return false;
	}
	CSteamID userID = (uint64)steam_id;
	return SteamGameServerStats()->UpdateUserAvgRateStat(userID, name.utf8().get_data(), this_session, session_length);
}



/////////////////////////////////////////////////
///// HTTP
/////////////////////////////////////////////////
//
// Creates a cookie container to store cookies during the lifetime of the process. This API is just for during process lifetime, after steam restarts no cookies are persisted and you have no way to access the cookie container across repeat executions of your process.
uint32_t SteamServer::createCookieContainer(bool allow_responses_to_modify){
	if(SteamHTTP() == NULL){
		return 0;
	}
	return SteamHTTP()->CreateCookieContainer(allow_responses_to_modify);
}

// Initializes a new HTTP request.
uint32_t SteamServer::createHTTPRequest(HTTPMethod request_method, const String& absolute_url){
	if(SteamHTTP() != NULL){
		return SteamHTTP()->CreateHTTPRequest((EHTTPMethod)request_method, absolute_url.utf8().get_data());
	}
	return HTTPREQUEST_INVALID_HANDLE;
}

// Defers a request which has already been sent by moving it at the back of the queue.
bool SteamServer::deferHTTPRequest(uint32 request_handle){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->DeferHTTPRequest(request_handle);
}

// Gets progress on downloading the body for the request.
float SteamServer::getHTTPDownloadProgressPct(uint32 request_handle){
	float percent_one = 0.0;
	if(SteamHTTP() != NULL){
		SteamHTTP()->GetHTTPDownloadProgressPct(request_handle, &percent_one);
	}
	return percent_one;
}

// Check if the reason the request failed was because we timed it out (rather than some harder failure).
bool SteamServer::getHTTPRequestWasTimedOut(uint32 request_handle){
	bool was_timed_out = false;
	if(SteamHTTP() != NULL){
		SteamHTTP()->GetHTTPRequestWasTimedOut(request_handle, &was_timed_out);
	}
	return was_timed_out;
}

// Gets the body data from an HTTP response.
PackedByteArray SteamServer::getHTTPResponseBodyData(uint32 request_handle, uint32 buffer_size){
	PackedByteArray body_data;
	body_data.resize(buffer_size);
	if(SteamHTTP() != NULL){
		SteamHTTP()->GetHTTPResponseBodyData(request_handle, body_data.ptrw(), buffer_size);
	}
	return body_data;
}

// Gets the size of the body data from an HTTP response.
uint32 SteamServer::getHTTPResponseBodySize(uint32 request_handle){
	uint32 body_size = 0;
	if(SteamHTTP() != NULL){
		SteamHTTP()->GetHTTPResponseBodySize(request_handle, &body_size);
	}
	return body_size;
}

// Checks if a header is present in an HTTP response and returns its size.
uint32 SteamServer::getHTTPResponseHeaderSize(uint32 request_handle, const String& header_name){
	uint32 response_header_size = 0;
	if(SteamHTTP() != NULL){
		SteamHTTP()->GetHTTPResponseHeaderSize(request_handle, header_name.utf8().get_data(), &response_header_size);
	}
	return response_header_size;
}

// Gets a header value from an HTTP response.
uint8 SteamServer::getHTTPResponseHeaderValue(uint32 request_handle, const String& header_name, uint32 buffer_size){
	uint8 value_buffer = 0;
	if(SteamHTTP() != NULL){
		SteamHTTP()->GetHTTPResponseHeaderValue(request_handle, header_name.utf8().get_data(), &value_buffer, buffer_size);
	}
	return value_buffer;
}

// Gets the body data from a streaming HTTP response.
uint8 SteamServer::getHTTPStreamingResponseBodyData(uint32 request_handle, uint32 offset, uint32 buffer_size){
	uint8 body_data_buffer = 0;
	if(SteamHTTP() != NULL){
		SteamHTTP()->GetHTTPStreamingResponseBodyData(request_handle, offset, &body_data_buffer, buffer_size);
	}
	return body_data_buffer;
}

// Prioritizes a request which has already been sent by moving it at the front of the queue.
bool SteamServer::prioritizeHTTPRequest(uint32 request_handle){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->PrioritizeHTTPRequest(request_handle);
}

// Releases a cookie container, freeing the memory allocated within Steam.
bool SteamServer::releaseCookieContainer(uint32 cookie_handle){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->ReleaseCookieContainer(cookie_handle);
}

// Releases an HTTP request handle, freeing the memory allocated within Steam.
bool SteamServer::releaseHTTPRequest(uint32 request_handle){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->ReleaseHTTPRequest(request_handle);
}

// Sends an HTTP request.
bool SteamServer::sendHTTPRequest(uint32 request_handle){
	if(SteamHTTP() == NULL){
		return false;
	}
	SteamAPICall_t call_handle;
	return SteamHTTP()->SendHTTPRequest(request_handle, &call_handle);
}

// Sends an HTTP request and streams the response back in chunks.
bool SteamServer::sendHTTPRequestAndStreamResponse(uint32 request_handle){
	if(SteamHTTP() == NULL){
		return false;
	}
	SteamAPICall_t call_handle;
	return SteamHTTP()->SendHTTPRequestAndStreamResponse(request_handle, &call_handle);
}

// Adds a cookie to the specified cookie container that will be used with future requests.
bool SteamServer::setHTTPCookie(uint32 cookie_handle, const String& host, const String& url, const String& cookie){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->SetCookie(cookie_handle, host.utf8().get_data(), url.utf8().get_data(), cookie.utf8().get_data());
}

// Set an absolute timeout in milliseconds for the HTTP request. This is the total time timeout which is different than the network activity timeout which is set with SetHTTPRequestNetworkActivityTimeout which can bump everytime we get more data.
bool SteamServer::setHTTPRequestAbsoluteTimeoutMS(uint32 request_handle, uint32 milliseconds){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->SetHTTPRequestAbsoluteTimeoutMS(request_handle, milliseconds);
}

// Set a context value for the request, which will be returned in the HTTPRequestCompleted_t callback after sending the request. This is just so the caller can easily keep track of which callbacks go with which request data. Must be called before sending the request.
bool SteamServer::setHTTPRequestContextValue(uint32 request_handle, uint64_t context_value){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->SetHTTPRequestContextValue(request_handle, context_value);
}

// Associates a cookie container to use for an HTTP request.
bool SteamServer::setHTTPRequestCookieContainer(uint32 request_handle, uint32 cookie_handle){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->SetHTTPRequestCookieContainer(request_handle, cookie_handle);
}

// Set a GET or POST parameter value on the HTTP request. Must be called prior to sending the request.
bool SteamServer::setHTTPRequestGetOrPostParameter(uint32 request_handle, const String& name, const String& value){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->SetHTTPRequestGetOrPostParameter(request_handle, name.utf8().get_data(), value.utf8().get_data());
}

// Set a request header value for the HTTP request. Must be called before sending the request.
bool SteamServer::setHTTPRequestHeaderValue(uint32 request_handle, const String& header_name, const String& header_value){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->SetHTTPRequestHeaderValue(request_handle, header_name.utf8().get_data(), header_value.utf8().get_data());
}

// Set the timeout in seconds for the HTTP request.
bool SteamServer::setHTTPRequestNetworkActivityTimeout(uint32 request_handle, uint32 timeout_seconds){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->SetHTTPRequestNetworkActivityTimeout(request_handle, timeout_seconds);
}

// Sets the body for an HTTP Post request.
uint8 SteamServer::setHTTPRequestRawPostBody(uint32 request_handle, const String& content_type, uint32 body_length){
	uint8 body = 0;
	if(SteamHTTP()){
		SteamHTTP()->SetHTTPRequestRawPostBody(request_handle, content_type.utf8().get_data(), &body, body_length);
	}
	return body;
}

// Sets that the HTTPS request should require verified SSL certificate via machines certificate trust store. This currently only works Windows and macOS.
bool SteamServer::setHTTPRequestRequiresVerifiedCertificate(uint32 request_handle, bool require_verified_certificate){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->SetHTTPRequestRequiresVerifiedCertificate(request_handle, require_verified_certificate);
}

// Set additional user agent info for a request.
bool SteamServer::setHTTPRequestUserAgentInfo(uint32 request_handle, const String& user_agent_info){
	if(SteamHTTP() == NULL){
		return false;
	}
	return SteamHTTP()->SetHTTPRequestUserAgentInfo(request_handle, user_agent_info.utf8().get_data());
}


/////////////////////////////////////////////////
///// INVENTORY
/////////////////////////////////////////////////
//
// When dealing with any inventory handles, you should call CheckResultSteamID on the result handle when it completes to verify that a remote player is not pretending to have a different user's inventory.
// Also, you must call DestroyResult on the provided inventory result when you are done with it.
//!
// Grant a specific one-time promotional item to the current user.
int32 SteamServer::addPromoItem(uint32 item){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		if(SteamInventory()->AddPromoItem(&new_inventory_handle, item)){
			// Update the internally stored handle
			inventory_handle = new_inventory_handle;
		}
	}
	return new_inventory_handle;
}

// Grant a specific one-time promotional items to the current user.
int32 SteamServer::addPromoItems(PackedInt64Array items){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		int count = items.size();
		SteamItemDef_t *new_items = new SteamItemDef_t[items.size()];
		for(int i = 0; i < count; i++){
			new_items[i] = items[i];
		}
		if(SteamInventory()->AddPromoItems(&new_inventory_handle, new_items, count)){
			// Update the internally stored handle
			inventory_handle = new_inventory_handle;
		}
		delete[] new_items;
	}
	return new_inventory_handle;
}

// Checks whether an inventory result handle belongs to the specified Steam ID.
bool SteamServer::checkResultSteamID(uint64_t steam_id_expected, int32 this_inventory_handle){
	if(SteamInventory() == NULL){
		return false;
	}
	CSteamID steam_id = (uint64)steam_id_expected;
	// If no inventory handle is passed, use internal one
	if(this_inventory_handle == 0){
		this_inventory_handle = inventory_handle;
	}
	return SteamInventory()->CheckResultSteamID((SteamInventoryResult_t)this_inventory_handle, steam_id);
}

// Consumes items from a user's inventory. If the quantity of the given item goes to zero, it is permanently removed.
int32 SteamServer::consumeItem(uint64_t item_consume, uint32 quantity){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
	 	if(SteamInventory()->ConsumeItem(&new_inventory_handle, (SteamItemInstanceID_t)item_consume, quantity)){
	 		// Update the internally stored handle
			inventory_handle = new_inventory_handle;
	 	}
	}
	return new_inventory_handle;
}

// Deserializes a result set and verifies the signature bytes.
int32 SteamServer::deserializeResult(PackedByteArray buffer){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		if(SteamInventory()->DeserializeResult(&new_inventory_handle, &buffer, buffer.size(), false)){
			// Update the internally stored handle
			inventory_handle = new_inventory_handle;
		}
	}
	return new_inventory_handle;
}

// Destroys a result handle and frees all associated memory.
void SteamServer::destroyResult(int this_inventory_handle){
	if(SteamInventory() != NULL){
		// If no inventory handle is passed, use internal one
		if(this_inventory_handle == 0){
			this_inventory_handle = inventory_handle;
		}	
		SteamInventory()->DestroyResult((SteamInventoryResult_t)this_inventory_handle);
	}
}

//! Grant one item in exchange for a set of other items.
int32 SteamServer::exchangeItems(const PackedInt64Array output_items, const uint32 output_quantity, const uint64_t input_items, const uint32 input_quantity){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		SteamItemDef_t *generated = new SteamItemDef_t[output_quantity];
		for(uint32 i = 0; i < output_quantity; i++){
			generated[i] = output_items[i];
		}
		if(SteamInventory()->ExchangeItems(&new_inventory_handle, generated, &output_quantity, 1, (const uint64 *)input_items, &input_quantity, 1)){
			// Update the internally stored handle
			inventory_handle = new_inventory_handle;
		}
		delete[] generated;
	}
	return new_inventory_handle;
}

// Grants specific items to the current user, for developers only.
int32 SteamServer::generateItems(const PackedInt64Array items, const uint32 quantity){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		SteamItemDef_t *generated = new SteamItemDef_t[quantity];
		for(uint32 i = 0; i < quantity; i++){
			generated[i] = items[i];
		}
		if(SteamInventory()->GenerateItems(&new_inventory_handle, generated, &quantity, items.size())){
			// Update the internally stored handle
			inventory_handle = new_inventory_handle;
		}
		delete[] generated;
	}
	return new_inventory_handle;
}

// Start retrieving all items in the current users inventory.
int32 SteamServer::getAllItems(){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		if(SteamInventory()->GetAllItems(&new_inventory_handle)){
			// Update the internally stored handle
			inventory_handle = new_inventory_handle;
		}
	}
	return new_inventory_handle;
}

// Gets a string property from the specified item definition.  Gets a property value for a specific item definition.
String SteamServer::getItemDefinitionProperty(uint32 definition, const String& name){
	if(SteamInventory() == NULL){
		return "";
	}
	uint32 buffer_size = STEAM_BUFFER_SIZE;
	char *buffer = new char[buffer_size];
	SteamInventory()->GetItemDefinitionProperty(definition, name.utf8().get_data(), buffer, &buffer_size);
	String property = String::utf8(buffer, buffer_size);
	delete[] buffer;
	return property;
}

// Gets the state of a subset of the current user's inventory.
int32 SteamServer::getItemsByID(const uint64_t id_array, uint32 count){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		if(SteamInventory()->GetItemsByID(&new_inventory_handle, (const uint64 *)id_array, count)){
			// Update the internally stored handle
			inventory_handle = new_inventory_handle;
		}
	}
	return new_inventory_handle;
}

// After a successful call to RequestPrices, you can call this method to get the pricing for a specific item definition.
uint64_t SteamServer::getItemPrice(uint32 definition){
	if(SteamInventory() == NULL){
		return 0;
	}
	uint64 price = 0;
	uint64 basePrice = 0;
	SteamInventory()->GetItemPrice(definition, &price, &basePrice);
	return price;
}

// After a successful call to RequestPrices, you can call this method to get all the pricing for applicable item definitions. Use the result of GetNumItemsWithPrices as the the size of the arrays that you pass in.
Array SteamServer::getItemsWithPrices(uint32 length){
	if(SteamInventory() == NULL){
		return Array();
	}
	// Create the return array
	Array price_array;
	// Create a temporary array
	SteamItemDef_t *ids = new SteamItemDef_t[length];
	uint64 *prices = new uint64[length];
	uint64 *base_prices = new uint64[length];
	if(SteamInventory()->GetItemsWithPrices(ids, prices, base_prices, length)){
		for(uint32 i = 0; i < length; i++){
			Dictionary price_group;
			price_group["item"] = ids[i];
			price_group["price"] = (uint64_t)prices[i];
			price_group["base_prices"] = (uint64_t)base_prices[i];
			price_array.append(price_group);
		}
	}
	delete[] ids;
	delete[] prices;
	delete[] base_prices;
	return price_array;
}

// After a successful call to RequestPrices, this will return the number of item definitions with valid pricing.
uint32 SteamServer::getNumItemsWithPrices(){
	if(SteamInventory() == NULL){
		return 0;
	}
	return SteamInventory()->GetNumItemsWithPrices();
}

// Gets the dynamic properties from an item in an inventory result set.
String SteamServer::getResultItemProperty(uint32 index, const String& name, int32 this_inventory_handle){
	if(SteamInventory() != NULL){
		// Set up variables to fill
		uint32 buffer_size = 256;
		char *value = new char[buffer_size];
		// If no inventory handle is passed, use internal one
		if(this_inventory_handle == 0){
			this_inventory_handle = inventory_handle;
		}
		SteamInventory()->GetResultItemProperty((SteamInventoryResult_t)this_inventory_handle, index, name.utf8().get_data(), (char*)value, &buffer_size);
		String property = value;
		delete[] value;
		return property;
	}
	return "";
}

// Get the items associated with an inventory result handle.
Array SteamServer::getResultItems(int32 this_inventory_handle){
	if(SteamInventory() == NULL){
		return Array();
	}
	// Set up return array
	Array items;
	uint32 size = 0;
	if(SteamInventory()->GetResultItems((SteamInventoryResult_t)this_inventory_handle, NULL, &size)){
		items.resize(size);
		SteamItemDetails_t *item_array = new SteamItemDetails_t[size];
		// If no inventory handle is passed, use internal one
		if(this_inventory_handle == 0){
			this_inventory_handle = inventory_handle;
		}
		if(SteamInventory()->GetResultItems((SteamInventoryResult_t)this_inventory_handle, item_array, &size)){
			for(uint32 i = 0; i < size; i++){
				items.push_back((uint64_t)item_array[i].m_itemId);
			}
		}
		delete[] item_array;
	}
	return items;
}

// Find out the status of an asynchronous inventory result handle.
String SteamServer::getResultStatus(int32 this_inventory_handle){
	if(SteamInventory() == NULL){
		return "";
	}
	// If no inventory handle is passed, use internal one
	if(this_inventory_handle == 0){
		this_inventory_handle = inventory_handle;
	}
	int result = SteamInventory()->GetResultStatus((SteamInventoryResult_t)this_inventory_handle);
	// Parse result
	if(result == k_EResultPending){
		return "Still in progress.";
	}
	else if(result == k_EResultOK){
		return "Finished successfully.";
	}
	else if(result == k_EResultExpired){
		return "Finished but may be out-of-date.";
	}
	else if(result == k_EResultInvalidParam){
		return "ERROR: invalid API call parameters.";
	}
	else if(result == k_EResultServiceUnavailable){
		return "ERROR: server temporarily down; retry later.";
	}
	else if(result == k_EResultLimitExceeded){
		return "ERROR: operation would exceed per-user inventory limits.";
	}
	else{
		return "ERROR: generic / unknown.";
	}
}

// Gets the server time at which the result was generated.
uint32 SteamServer::getResultTimestamp(int32 this_inventory_handle){
	if(SteamInventory() == NULL){
		return 0;
	}
	// If no inventory handle is passed, use internal one
	if(this_inventory_handle == 0){
		this_inventory_handle = inventory_handle;
	}
	return SteamInventory()->GetResultTimestamp((SteamInventoryResult_t)this_inventory_handle);
}

// Grant all potential one-time promotional items to the current user.
int32 SteamServer::grantPromoItems(){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		if(SteamInventory()->GrantPromoItems(&new_inventory_handle)){
			// Update the internally stored handle
			inventory_handle = new_inventory_handle;
		}
	}
	return new_inventory_handle;
}

// Triggers an asynchronous load and refresh of item definitions.
bool SteamServer::loadItemDefinitions(){
	if(SteamInventory() == NULL){
		return false;
	}
	return SteamInventory()->LoadItemDefinitions();
}

// Request the list of "eligible" promo items that can be manually granted to the given user.
void SteamServer::requestEligiblePromoItemDefinitionsIDs(uint64_t steam_id){
	if(SteamInventory() != NULL){
		CSteamID user_id = (uint64)steam_id;
		SteamAPICall_t api_call = SteamInventory()->RequestEligiblePromoItemDefinitionsIDs(user_id);
		callResultEligiblePromoItemDefIDs.Set(api_call, this, &SteamServer::inventory_eligible_promo_item);
	}
}

// Request prices for all item definitions that can be purchased in the user's local currency. A SteamInventoryRequestPricesResult_t call result will be returned with the user's local currency code. After that, you can call GetNumItemsWithPrices and GetItemsWithPrices to get prices for all the known item definitions, or GetItemPrice for a specific item definition.
void SteamServer::requestPrices(){
	if(SteamInventory() != NULL){
		SteamAPICall_t api_call = SteamInventory()->RequestPrices();
		callResultRequestPrices.Set(api_call, this, &SteamServer::inventory_request_prices_result);
	}
}

// Serialized result sets contain a short signature which can't be forged or replayed across different game sessions.
String SteamServer::serializeResult(int32 this_inventory_handle){
	String result_serialized;
	if(SteamInventory() != NULL){
		// If no inventory handle is passed, use internal one
		if(this_inventory_handle == 0){
			this_inventory_handle = inventory_handle;
		}
		// Set up return array
		uint32 buffer_size = STEAM_BUFFER_SIZE;
		char *buffer = new char[buffer_size];
		if(SteamInventory()->SerializeResult((SteamInventoryResult_t)this_inventory_handle, buffer, &buffer_size)){
			result_serialized = String::utf8(buffer, buffer_size);
		}
		delete[] buffer;
	}
	return result_serialized;
}

// Starts the purchase process for the user, given a "shopping cart" of item definitions that the user would like to buy. The user will be prompted in the Steam Overlay to complete the purchase in their local currency, funding their Steam Wallet if necessary, etc.
void SteamServer::startPurchase(const PackedInt64Array items, const uint32 quantity){
	if(SteamInventory() != NULL){
		SteamItemDef_t *purchases = new SteamItemDef_t[quantity];
		for(uint32 i = 0; i < quantity; i++){
			purchases[i] = items[i];
		}
		SteamAPICall_t api_call = SteamInventory()->StartPurchase(purchases, &quantity, items.size());
		callResultStartPurchase.Set(api_call, this, &SteamServer::inventory_start_purchase_result);
		delete[] purchases;
	}
}

// Transfer items between stacks within a user's inventory.
int32 SteamServer::transferItemQuantity(uint64_t item_id, uint32 quantity, uint64_t item_destination, bool split){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		if(split){
			if(SteamInventory()->TransferItemQuantity(&new_inventory_handle, (SteamItemInstanceID_t)item_id, quantity, k_SteamItemInstanceIDInvalid)){
				// Update the internally stored handle
				inventory_handle = new_inventory_handle;
			}
		}
		else{
			if(SteamInventory()->TransferItemQuantity(&new_inventory_handle, (SteamItemInstanceID_t)item_id, quantity, (SteamItemInstanceID_t)item_destination)){
				// Update the internally stored handle
				inventory_handle = new_inventory_handle;
			}
		}
	}
	return new_inventory_handle;
}

// Trigger an item drop if the user has played a long enough period of time.
int32 SteamServer::triggerItemDrop(uint32 definition){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		if(SteamInventory()->TriggerItemDrop(&new_inventory_handle, (SteamItemDef_t)definition)){
			// Update the internally stored handle
			inventory_handle = new_inventory_handle;
		}
	}
	return new_inventory_handle;
}

// Starts a transaction request to update dynamic properties on items for the current user. This call is rate-limited by user, so property modifications should be batched as much as possible (e.g. at the end of a map or game session). After calling SetProperty or RemoveProperty for all the items that you want to modify, you will need to call SubmitUpdateProperties to send the request to the Steam servers. A SteamInventoryResultReady_t callback will be fired with the results of the operation.
void SteamServer::startUpdateProperties(){
	if(SteamInventory() != NULL){
		inventory_update_handle = SteamInventory()->StartUpdateProperties();
	}
}

// Submits the transaction request to modify dynamic properties on items for the current user. See StartUpdateProperties.
int32 SteamServer::submitUpdateProperties(uint64_t this_inventory_update_handle){
	int32 new_inventory_handle = 0;
	if(SteamInventory() != NULL){
		// If no inventory update handle is passed, use internal one
		if(this_inventory_update_handle == 0){
			this_inventory_update_handle = inventory_update_handle;
		}
		if(SteamInventory()->SubmitUpdateProperties((SteamInventoryUpdateHandle_t)this_inventory_update_handle, &new_inventory_handle)){
			// Update the internally stored handle
			inventory_handle = new_inventory_handle;
		}
	}
	return new_inventory_handle;
}

// Removes a dynamic property for the given item.
bool SteamServer::removeProperty(uint64_t item_id, const String& name, uint64_t this_inventory_update_handle){
	if(SteamInventory() == NULL){
		return false;
	}
	// If no inventory update handle is passed, use internal one
	if(this_inventory_update_handle == 0){
		this_inventory_update_handle = inventory_update_handle;
	}
	return SteamInventory()->RemoveProperty((SteamInventoryUpdateHandle_t)this_inventory_update_handle, (SteamItemInstanceID_t)item_id, name.utf8().get_data());
}

// Sets a dynamic property for the given item. Supported value types are strings.
bool SteamServer::setPropertyString(uint64_t item_id, const String& name, const String& value, uint64_t this_inventory_update_handle){
	if(SteamInventory() == NULL){
		return false;
	}
	// If no inventory update handle is passed, use internal one
	if(this_inventory_update_handle == 0){
		this_inventory_update_handle = inventory_update_handle;
	}
	return SteamInventory()->SetProperty((SteamInventoryUpdateHandle_t)this_inventory_update_handle, (SteamItemInstanceID_t)item_id, name.utf8().get_data(), value.utf8().get_data());
}

// Sets a dynamic property for the given item. Supported value types are boolean.
bool SteamServer::setPropertyBool(uint64_t item_id, const String& name, bool value, uint64_t this_inventory_update_handle){
	if(SteamInventory() == NULL){
		return false;
	}
	// If no inventory update handle is passed, use internal one
	if(this_inventory_update_handle == 0){
		this_inventory_update_handle = inventory_update_handle;
	}
	return SteamInventory()->SetProperty((SteamInventoryUpdateHandle_t)this_inventory_update_handle, (SteamItemInstanceID_t)item_id, name.utf8().get_data(), value);
}

// Sets a dynamic property for the given item. Supported value types are 64 bit integers.
bool SteamServer::setPropertyInt(uint64_t item_id, const String& name, uint64_t value, uint64_t this_inventory_update_handle){
	if(SteamInventory() == NULL){
		return false;
	}
	// If no inventory update handle is passed, use internal one
	if(this_inventory_update_handle == 0){
		this_inventory_update_handle = inventory_update_handle;
	}
	return SteamInventory()->SetProperty((SteamInventoryUpdateHandle_t)this_inventory_update_handle, (SteamItemInstanceID_t)item_id, name.utf8().get_data(), (int64)value);
}

// Sets a dynamic property for the given item. Supported value types are 32 bit floats.
bool SteamServer::setPropertyFloat(uint64_t item_id, const String& name, float value, uint64_t this_inventory_update_handle){
	if(SteamInventory() == NULL){
		return false;
	}
	// If no inventory update handle is passed, use internal one
	if(this_inventory_update_handle == 0){
		this_inventory_update_handle = inventory_update_handle;
	}
	return SteamInventory()->SetProperty((SteamInventoryUpdateHandle_t)this_inventory_update_handle, (SteamItemInstanceID_t)item_id, name.utf8().get_data(), value);
}


/////////////////////////////////////////////////
///// NETWORKING
/////////////////////////////////////////////////
//
// This allows the game to specify accept an incoming packet.
bool SteamServer::acceptP2PSessionWithUser(uint64_t steam_id_remote) {
	if (SteamNetworking() == NULL) {
		return false;
	}
	CSteamID steam_id = createSteamID(steam_id_remote);
	return SteamNetworking()->AcceptP2PSessionWithUser(steam_id);
}

// Allow or disallow P2P connections to fall back to being relayed through the Steam servers if a direct connection or NAT-traversal cannot be established.
bool SteamServer::allowP2PPacketRelay(bool allow) {
	if (SteamNetworking() == NULL) {
		return false;
	}
	return SteamNetworking()->AllowP2PPacketRelay(allow);
}

// Closes a P2P channel when you're done talking to a user on the specific channel.
bool SteamServer::closeP2PChannelWithUser(uint64_t steam_id_remote, int channel) {
	if (SteamNetworking() == NULL) {
		return false;
	}
	CSteamID steam_id = createSteamID(steam_id_remote);
	return SteamNetworking()->CloseP2PChannelWithUser(steam_id, channel);
}

// This should be called when you're done communicating with a user, as this will free up all of the resources allocated for the connection under-the-hood.
bool SteamServer::closeP2PSessionWithUser(uint64_t steam_id_remote) {
	if (SteamNetworking() == NULL) {
		return false;
	}
	CSteamID steam_id = createSteamID(steam_id_remote);
	return SteamNetworking()->CloseP2PSessionWithUser(steam_id);
}

// Fills out a P2PSessionState_t structure with details about the connection like whether or not there is an active connection.
Dictionary SteamServer::getP2PSessionState(uint64_t steam_id_remote) {
	Dictionary result;
	if (SteamNetworking() == NULL) {
		return result;
	}
	CSteamID steam_id = createSteamID(steam_id_remote);
	P2PSessionState_t p2pSessionState;
	bool success = SteamNetworking()->GetP2PSessionState(steam_id, &p2pSessionState);
	if (!success) {
		return result;
	}
	result["connection_active"] = p2pSessionState.m_bConnectionActive; // true if we've got an active open connection
	result["connecting"] = p2pSessionState.m_bConnecting; // true if we're currently trying to establish a connection
	result["session_error"] = p2pSessionState.m_eP2PSessionError; // last error recorded (see enum in isteamnetworking.h)
	result["using_relay"] = p2pSessionState.m_bUsingRelay; // true if it's going through a relay server (TURN)
	result["bytes_queued_for_send"] = p2pSessionState.m_nBytesQueuedForSend;
	result["packets_queued_for_send"] = p2pSessionState.m_nPacketsQueuedForSend;
	result["remote_ip"] = p2pSessionState.m_nRemoteIP; // potential IP:Port of remote host. Could be TURN server.
	result["remote_port"] = p2pSessionState.m_nRemotePort; // Only exists for compatibility with older authentication api's
	return result;
}

// Calls IsP2PPacketAvailable() under the hood, returns the size of the available packet or zero if there is no such packet.
uint32_t SteamServer::getAvailableP2PPacketSize(int channel){
	if (SteamNetworking() == NULL) {
		return 0;
	}
	uint32_t messageSize = 0;
	return (SteamNetworking()->IsP2PPacketAvailable(&messageSize, channel)) ? messageSize : 0;
}

// Reads in a packet that has been sent from another user via SendP2PPacket.
Dictionary SteamServer::readP2PPacket(uint32_t packet, int channel){
	Dictionary result;
	if (SteamNetworking() == NULL) {
		return result;
	}
	PackedByteArray data;
	data.resize(packet);
	CSteamID steam_id;
	uint32_t bytesRead = 0;
	if (SteamNetworking()->ReadP2PPacket(data.ptrw(), packet, &bytesRead, &steam_id, channel)){
		data.resize(bytesRead);
		uint64_t steam_id_remote = steam_id.ConvertToUint64();
		result["data"] = data;
		result["steam_id_remote"] = steam_id_remote;
	}
	else {
		data.resize(0);
	}
	return result;
}

// Sends a P2P packet to the specified user.
bool SteamServer::sendP2PPacket(uint64_t steam_id_remote, PackedByteArray data, P2PSend send_type, int channel){
	if (SteamNetworking() == NULL) {
		return false;
	}
	CSteamID steam_id = createSteamID(steam_id_remote);
	return SteamNetworking()->SendP2PPacket(steam_id, data.ptr(), data.size(), EP2PSend(send_type), channel);
}


/////////////////////////////////////////////////
///// NETWORKING MESSAGES
/////////////////////////////////////////////////
//
// AcceptSessionWithUser() should only be called in response to a SteamP2PSessionRequest_t callback SteamP2PSessionRequest_t will be posted if another user tries to send you a message, and you haven't tried to talk to them.
bool SteamServer::acceptSessionWithUser(const String& identity_reference){
	if(SteamNetworkingMessages() == NULL){
		return false;
	}
	return SteamNetworkingMessages()->AcceptSessionWithUser(networking_identities[identity_reference.utf8().get_data()]);
}

// Call this  when you're done talking to a user on a specific channel. Once all open channels to a user have been closed, the open session to the user will be closed, and any new data from this user will trigger a SteamP2PSessionRequest_t callback.
bool SteamServer::closeChannelWithUser(const String& identity_reference, int channel){
	if(SteamNetworkingMessages() == NULL){
		return false;
	}
	return SteamNetworkingMessages()->CloseChannelWithUser(networking_identities[identity_reference.utf8().get_data()], channel);
}

// Call this when you're done talking to a user to immediately free up resources under-the-hood.
bool SteamServer::closeSessionWithUser(const String& identity_reference){
	if(SteamNetworkingMessages() == NULL){
		return false;
	}
	return SteamNetworkingMessages()->CloseSessionWithUser(networking_identities[identity_reference.utf8().get_data()]);
}

// Returns information about the latest state of a connection, if any, with the given peer.
Dictionary SteamServer::getSessionConnectionInfo(const String& identity_reference, bool get_connection, bool get_status){
	Dictionary connection_info;
	if(SteamNetworkingMessages() != NULL){
		SteamNetConnectionInfo_t this_info;
		SteamNetConnectionRealTimeStatus_t this_status;
		int connection_state = SteamNetworkingMessages()->GetSessionConnectionInfo(networking_identities[identity_reference.utf8().get_data()], &this_info, &this_status);
		// Parse the data to a dictionary
		connection_info["connection_state"] = connection_state;
		// If getting the connection information
		if(get_connection){
			char identity[STEAM_BUFFER_SIZE];
			this_info.m_identityRemote.ToString(identity, STEAM_BUFFER_SIZE);
			connection_info["identity"] = identity;
			connection_info["user_data"] = (uint64_t)this_info.m_nUserData;
			connection_info["listen_socket"] = this_info.m_hListenSocket;
			char ip_address[STEAM_BUFFER_SIZE];
			this_info.m_addrRemote.ToString(ip_address, STEAM_BUFFER_SIZE, true);
			connection_info["remote_address"] = ip_address;
			connection_info["remote_pop"] = this_info.m_idPOPRemote;
			connection_info["pop_relay"] = this_info.m_idPOPRelay;
			connection_info["connection_state"] = this_info.m_eState;
			connection_info["end_reason"] = this_info.m_eEndReason;
			connection_info["end_debug"] = this_info.m_szEndDebug;
			connection_info["debug_description"] = this_info.m_szConnectionDescription;
		}
		// If getting the quick status
		if(get_status){
			connection_info["state"] = this_status.m_eState;
			connection_info["ping"] = this_status.m_nPing;
			connection_info["local_quality"] = this_status.m_flConnectionQualityLocal;
			connection_info["remote_quality"] = this_status.m_flConnectionQualityRemote;
			connection_info["packets_out_per_second"] = this_status.m_flOutPacketsPerSec;
			connection_info["bytes_out_per_second"] = this_status.m_flOutBytesPerSec;
			connection_info["packets_in_per_second"] = this_status.m_flInPacketsPerSec;
			connection_info["bytes_in_per_second"] = this_status.m_flInBytesPerSec;
			connection_info["send_rate"] = this_status.m_nSendRateBytesPerSecond;
			connection_info["pending_unreliable"] = this_status.m_cbPendingUnreliable;
			connection_info["pending_reliable"] = this_status.m_cbPendingReliable;
			connection_info["sent_unacknowledged_reliable"] = this_status.m_cbSentUnackedReliable;
			connection_info["queue_time"] = (uint64_t)this_status.m_usecQueueTime;
		}
	}
	return connection_info;
}

// Reads the next message that has been sent from another user via SendMessageToUser() on the given channel. Returns number of messages returned into your list.  (0 if no message are available on that channel.)
Array SteamServer::receiveMessagesOnChannel(int channel, int max_messages){
	Array messages;
	if(SteamNetworkingMessages() != NULL){
		// Allocate the space for the messages
		SteamNetworkingMessage_t** channel_messages = new SteamNetworkingMessage_t*[max_messages];
		// Get the messages
		int available_messages = SteamNetworkingMessages()->ReceiveMessagesOnChannel(channel, channel_messages, max_messages);
		// Loop through and create the messages as dictionaries then add to the messages array
		for(int i = 0; i < available_messages; i++){
			// Set up the mesage dictionary
			Dictionary message;
			// Get the data / message
			int message_size = channel_messages[i]->m_cbSize;
			PackedByteArray data;
			data.resize(message_size);
			uint8_t* source_data = (uint8_t*)channel_messages[i]->m_pData;
			uint8_t* output_data = data.ptrw();
			for(int j = 0; j < message_size; j++){
				output_data[j] = source_data[j];
			}
			message["payload"] = data;
			message["size"] = message_size;
			message["connection"] = channel_messages[i]->m_conn;
			char identity[STEAM_BUFFER_SIZE];
			channel_messages[i]->m_identityPeer.ToString(identity, STEAM_BUFFER_SIZE);
			message["identity"] = identity;
			message["receiver_user_data"] = (uint64_t)channel_messages[i]->m_nConnUserData;	// Not used when sending messages
			message["time_received"] = (uint64_t)channel_messages[i]->m_usecTimeReceived;
			message["message_number"] = (uint64_t)channel_messages[i]->m_nMessageNumber;
			message["channel"] = channel_messages[i]->m_nChannel;
			message["flags"] = channel_messages[i]->m_nFlags;
			message["sender_user_data"] = (uint64_t)channel_messages[i]->m_nUserData;	// Not used when receiving messages
			messages.append(message);
			// Release the message
			channel_messages[i]->Release();
		}
		delete [] channel_messages;
	}
	return messages;
}

// Sends a message to the specified host. If we don't already have a session with that user, a session is implicitly created. There might be some handshaking that needs to happen before we can actually begin sending message data.
int SteamServer::sendMessageToUser(const String& identity_reference, const PackedByteArray data, int flags, int channel){
	if(SteamNetworkingMessages() == NULL){
		return 0;
	}
	return SteamNetworkingMessages()->SendMessageToUser(networking_identities[identity_reference.utf8().get_data()], data.ptr(), data.size(), flags, channel);
}


/////////////////////////////////////////////////
///// NETWORKING SOCKETS
/////////////////////////////////////////////////
//
// Creates a "server" socket that listens for clients to connect to by calling ConnectByIPAddress, over ordinary UDP (IPv4 or IPv6)
uint32 SteamServer::createListenSocketIP(const String& ip_reference, Array options){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	const SteamNetworkingConfigValue_t *these_options = convertOptionsArray(options);
	uint32 listen_socket = SteamNetworkingSockets()->CreateListenSocketIP(ip_addresses[ip_reference.utf8().get_data()], options.size(), these_options);
	delete[] these_options;
	return listen_socket;
}

// Like CreateListenSocketIP, but clients will connect using ConnectP2P. The connection will be relayed through the Valve network.
uint32 SteamServer::createListenSocketP2P(int virtual_port, Array options){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	const SteamNetworkingConfigValue_t *these_options = convertOptionsArray(options);
	uint32 listen_socket = SteamNetworkingSockets()->CreateListenSocketP2P(virtual_port, options.size(), these_options);
	delete[] these_options;
	return listen_socket;
}

// Begin connecting to a server that is identified using a platform-specific identifier. This uses the default rendezvous service, which depends on the platform and library configuration. (E.g. on Steam, it goes through the steam backend.) The traffic is relayed over the Steam Datagram Relay network.
uint32 SteamServer::connectP2P(const String& identity_reference, int virtual_port, Array options){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	return SteamNetworkingSockets()->ConnectP2P(networking_identities[identity_reference.utf8().get_data()], virtual_port, sizeof(options), convertOptionsArray(options));
}

// Begin connecting to a server listen socket that is identified using an [ip-address]:[port], i.e. 127.0.0.1:27015. Used with createListenSocketIP
uint32 SteamServer::connectByIPAddress(const String& ip_address_with_port, Array options){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	
	SteamNetworkingIPAddr steamAddr;
	steamAddr.Clear();
	steamAddr.ParseString(ip_address_with_port.utf8().get_data());

	return SteamNetworkingSockets()->ConnectByIPAddress(steamAddr, options.size(), convertOptionsArray(options));
}

// Client call to connect to a server hosted in a Valve data center, on the specified virtual port. You must have placed a ticket for this server into the cache, or else this connect attempt will fail!
uint32 SteamServer::connectToHostedDedicatedServer(const String& identity_reference, int virtual_port, Array options){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	const SteamNetworkingConfigValue_t *these_options = convertOptionsArray(options);
	uint32 listen_socket = SteamNetworkingSockets()->ConnectToHostedDedicatedServer(networking_identities[identity_reference.utf8().get_data()], virtual_port, options.size(), these_options);
	delete[] these_options;
	return listen_socket;
}

// Accept an incoming connection that has been received on a listen socket.
int SteamServer::acceptConnection(uint32 connection_handle){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	return SteamNetworkingSockets()->AcceptConnection((HSteamNetConnection)connection_handle);
}

// Disconnects from the remote host and invalidates the connection handle. Any unread data on the connection is discarded.
bool SteamServer::closeConnection(uint32 peer, int reason, const String& debug_message, bool linger){
	if(SteamNetworkingSockets() == NULL){
		return false;
	}
	return SteamNetworkingSockets()->CloseConnection((HSteamNetConnection)peer, reason, debug_message.utf8().get_data(), linger);
}

// Destroy a listen socket. All the connections that were accepted on the listen socket are closed ungracefully.
bool SteamServer::closeListenSocket(uint32 socket){
	if(SteamNetworkingSockets() == NULL){
		return false;
	}
	return SteamNetworkingSockets()->CloseListenSocket((HSteamListenSocket)socket);
}

// Create a pair of connections that are talking to each other, e.g. a loopback connection. This is very useful for testing, or so that your client/server code can work the same even when you are running a local "server".
Dictionary SteamServer::createSocketPair(bool loopback, const String& identity_reference1, const String& identity_reference2){
	// Create a dictionary to populate
	Dictionary connection_pair;
	if(SteamNetworkingSockets() != NULL){
		// Turn the strings back to structs - Should be a check for failure to parse from string
		const SteamNetworkingIdentity identity_struct1 = networking_identities[identity_reference1.utf8().get_data()];
		const SteamNetworkingIdentity identity_struct2 = networking_identities[identity_reference2.utf8().get_data()];
		// Get connections
		uint32 connection1 = 0;
		uint32 connection2 = 0;
		bool success = SteamNetworkingSockets()->CreateSocketPair(&connection1, &connection2, loopback, &identity_struct1, &identity_struct2);
		// Populate the dictionary
		connection_pair["success"] = success;
		connection_pair["connection1"] = connection1;
		connection_pair["connection2"] = connection2;
	}
	return connection_pair;
}

// Send a message to the remote host on the specified connection.
Dictionary SteamServer::sendMessageToConnection(uint32 connection_handle, const PackedByteArray data, int flags){
	Dictionary message_response;
	if(SteamNetworkingSockets() != NULL){
		int64 number;
		int result = SteamNetworkingSockets()->SendMessageToConnection((HSteamNetConnection)connection_handle, data.ptr(), data.size(), flags, &number);
		// Populate the dictionary
		message_response["result"] = result;
		message_response["message_number"] = (uint64_t)number;
	}
	return message_response;
}

// Send one or more messages without copying the message payload. This is the most efficient way to send messages. To use this function, you must first allocate a message object using ISteamNetworkingUtils::AllocateMessage. (Do not declare one on the stack or allocate your own.)
void SteamServer::sendMessages(int messages, const PackedByteArray data, uint32 connection_handle, int flags){
	if(SteamNetworkingSockets() != NULL){
		SteamNetworkingMessage_t *networkMessage;
		networkMessage = SteamNetworkingUtils()->AllocateMessage(0);
		networkMessage->m_pData = (void *)data.ptr();
		networkMessage->m_cbSize = data.size();
		networkMessage->m_conn = (HSteamNetConnection)connection_handle;
		networkMessage->m_nFlags = flags;
		int64 result;
		SteamNetworkingSockets()->SendMessages(messages, &networkMessage, &result);
		// Release the message
		networkMessage->Release();
	}
}

// Flush any messages waiting on the Nagle timer and send them at the next transmission opportunity (often that means right now).
int SteamServer::flushMessagesOnConnection(uint32 connection_handle){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	return SteamNetworkingSockets()->FlushMessagesOnConnection((HSteamNetConnection)connection_handle);
}

// Fetch the next available message(s) from the connection, if any. Returns the number of messages returned into your array, up to nMaxMessages. If the connection handle is invalid, -1 is returned. If no data is available, 0, is returned.
Array SteamServer::receiveMessagesOnConnection(uint32 connection_handle, int max_messages){
	Array messages;
	if(SteamNetworkingSockets() != NULL){
		// Allocate the space for the messages
		SteamNetworkingMessage_t** connection_messages = new SteamNetworkingMessage_t*[max_messages];
		// Get the messages
		int available_messages = SteamNetworkingSockets()->ReceiveMessagesOnConnection((HSteamNetConnection)connection_handle, connection_messages, max_messages);
		// Loop through and create the messages as dictionaries then add to the messages array
		for(int i = 0; i < available_messages; i++){
			// Create the message dictionary to send back
			Dictionary message;
			// Get the message data
			int message_size = connection_messages[i]->m_cbSize;
			PackedByteArray data;
			data.resize(message_size);
			uint8_t* source_data = (uint8_t*)connection_messages[i]->m_pData;
			uint8_t* output_data = data.ptrw();
			for(int j = 0; j < message_size; j++){
				output_data[j] = source_data[j];
			}
			message["payload"] = data;
			message["size"] = message_size;
			message["connection"] = connection_messages[i]->m_conn;
			char identity[STEAM_BUFFER_SIZE];
			connection_messages[i]->m_identityPeer.ToString(identity, STEAM_BUFFER_SIZE);
			message["identity"] = identity;
			message["receiver_user_data"] = (uint64_t)connection_messages[i]->m_nConnUserData; // Not used when sending messages
			message["time_received"] = (uint64_t)connection_messages[i]->m_usecTimeReceived;
			message["message_number"] = (uint64_t)connection_messages[i]->m_nMessageNumber;
			message["channel"] = connection_messages[i]->m_nChannel;
			message["flags"] = connection_messages[i]->m_nFlags;
			message["sender_user_data"] = (uint64_t)connection_messages[i]->m_nUserData; // Not used when receiving messages
			messages.append(message);
			// Release the message
			connection_messages[i]->Release();
		}
		delete [] connection_messages;
	}
	return messages;
}

// Create a new poll group.
uint32 SteamServer::createPollGroup(){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	return SteamNetworkingSockets()->CreatePollGroup();
}

// Destroy a poll group created with CreatePollGroup.
bool SteamServer::destroyPollGroup(uint32 poll_group){
	if(SteamNetworkingSockets() == NULL){
		return false;
	}
	return SteamNetworkingSockets()->DestroyPollGroup((HSteamNetPollGroup)poll_group);
}

// Assign a connection to a poll group. Note that a connection may only belong to a single poll group. Adding a connection to a poll group implicitly removes it from any other poll group it is in.
bool SteamServer::setConnectionPollGroup(uint32 connection_handle, uint32 poll_group){
	if(SteamNetworkingSockets() == NULL){
		return false;
	}
	return SteamNetworkingSockets()->SetConnectionPollGroup((HSteamNetConnection)connection_handle, (HSteamNetPollGroup)poll_group);
}

// Same as ReceiveMessagesOnConnection, but will return the next messages available on any connection in the poll group. Examine SteamNetworkingMessage_t::m_conn to know which connection. (SteamNetworkingMessage_t::m_nConnUserData might also be useful.)
Array SteamServer::receiveMessagesOnPollGroup(uint32 poll_group, int max_messages){
	Array messages;
	if(SteamNetworkingSockets() != NULL){
		// Allocate the space for the messages
		SteamNetworkingMessage_t** poll_messages = new SteamNetworkingMessage_t*[max_messages];
		// Get the messages
		int available_messages = SteamNetworkingSockets()->ReceiveMessagesOnPollGroup((HSteamNetPollGroup)poll_group, poll_messages, max_messages);
		// Loop through and create the messages as dictionaries then add to the messages array
		for(int i = 0; i < available_messages; i++){
			// Create the message dictionary to send back
			Dictionary message;
			// Get the message data
			int message_size = poll_messages[i]->m_cbSize;
			PackedByteArray data;
			data.resize(message_size);
			uint8_t* source_data = (uint8_t*)poll_messages[i]->m_pData;
			uint8_t* output_data = data.ptrw();
			for(int j = 0; j < message_size; j++){
				output_data[j] = source_data[j];
			}
			message["payload"] = data;
			message["size"] = message_size;
			message["connection"] = poll_messages[i]->m_conn;
			char identity[STEAM_BUFFER_SIZE];
			poll_messages[i]->m_identityPeer.ToString(identity, STEAM_BUFFER_SIZE);
			message["identity"] = identity;
			message["user_data"] = (uint64_t)poll_messages[i]->m_nConnUserData;
			message["time_received"] = (uint64_t)poll_messages[i]->m_usecTimeReceived;
			message["message_number"] = (uint64_t)poll_messages[i]->m_nMessageNumber;
			message["channel"] = poll_messages[i]->m_nChannel;
			message["flags"] = poll_messages[i]->m_nFlags;
			message["user_data"] = (uint64_t)poll_messages[i]->m_nUserData;
			messages.append(message);
			// Release the message
			poll_messages[i]->Release();
		}
		delete [] poll_messages;
	}
	return messages;
}

// Returns basic information about the high-level state of the connection. Returns false if the connection handle is invalid.
Dictionary SteamServer::getConnectionInfo(uint32 connection_handle){
	Dictionary connection_info;
	if(SteamNetworkingSockets() != NULL){
		SteamNetConnectionInfo_t info;
		if(SteamNetworkingSockets()->GetConnectionInfo((HSteamNetConnection)connection_handle, &info)){
			char identity[STEAM_BUFFER_SIZE];
			info.m_identityRemote.ToString(identity, STEAM_BUFFER_SIZE);
			connection_info["identity"] = identity;
			connection_info["user_data"] = (uint64_t)info.m_nUserData;
			connection_info["listen_socket"] = info.m_hListenSocket;
			char ip_address[STEAM_BUFFER_SIZE];
			info.m_addrRemote.ToString(ip_address, STEAM_BUFFER_SIZE, true);
			connection_info["remote_address"] = ip_address;
			connection_info["remote_pop"] = info.m_idPOPRemote;
			connection_info["pop_relay"] = info.m_idPOPRelay;
			connection_info["connection_state"] = info.m_eState;
			connection_info["end_reason"] = info.m_eEndReason;
			connection_info["end_debug"] = info.m_szEndDebug;
			connection_info["debug_description"] = info.m_szConnectionDescription;
		}
	}
	return connection_info;
}

// Returns very detailed connection stats in diagnostic text format. Useful for dumping to a log, etc. The format of this information is subject to change.
Dictionary SteamServer::getDetailedConnectionStatus(uint32 connection){
	Dictionary connectionStatus;
	if(SteamNetworkingSockets() != NULL){
		char buffer[STEAM_LARGE_BUFFER_SIZE];
		int success = SteamNetworkingSockets()->GetDetailedConnectionStatus((HSteamNetConnection)connection, buffer, STEAM_LARGE_BUFFER_SIZE);
		// Add data to dictionary
		connectionStatus["success"] = success;
		connectionStatus["status"] = buffer;
	}
	// Send the data back to the user
	return connectionStatus; 
}

// Fetch connection user data. Returns -1 if handle is invalid or if you haven't set any userdata on the connection.
uint64_t SteamServer::getConnectionUserData(uint32 peer){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	return SteamNetworkingSockets()->GetConnectionUserData((HSteamNetConnection)peer);
}

// Set a name for the connection, used mostly for debugging
void SteamServer::setConnectionName(uint32 peer, const String& name){
	if(SteamNetworkingSockets() != NULL){
		SteamNetworkingSockets()->SetConnectionName((HSteamNetConnection)peer, name.utf8().get_data());
	}
}

// Fetch connection name into your buffer, which is at least nMaxLen bytes. Returns false if handle is invalid.
String SteamServer::getConnectionName(uint32 peer){
	// Set empty string variable for use
	String connection_name = "";
	if(SteamNetworkingSockets() != NULL){
		char name[STEAM_BUFFER_SIZE];
		if(SteamNetworkingSockets()->GetConnectionName((HSteamNetConnection)peer, name, STEAM_BUFFER_SIZE)){
			connection_name += name;	
		}
	}
	return connection_name;
}

// Returns local IP and port that a listen socket created using CreateListenSocketIP is bound to.
bool SteamServer::getListenSocketAddress(uint32 socket){
	if(SteamNetworkingSockets() == NULL){
		return false;
	}
	SteamNetworkingIPAddr address;
	return SteamNetworkingSockets()->GetListenSocketAddress((HSteamListenSocket)socket, &address);
}

// Get the identity assigned to this interface.
String SteamServer::getIdentity(){
	String identity_string = "";
	if(SteamNetworkingSockets() != NULL){
		SteamNetworkingIdentity this_identity;
		if(SteamNetworkingSockets()->GetIdentity(&this_identity)){
			char *this_buffer = new char[128];
			this_identity.ToString(this_buffer, 128);
			identity_string = String(this_buffer);
			delete[] this_buffer;
		}
	}
	return identity_string;
}

// Indicate our desire to be ready participate in authenticated communications. If we are currently not ready, then steps will be taken to obtain the necessary certificates. (This includes a certificate for us, as well as any CA certificates needed to authenticate peers.)
SteamServer::NetworkingAvailability SteamServer::initAuthentication(){
	if(SteamNetworkingSockets() == NULL){
		return NETWORKING_AVAILABILITY_UNKNOWN;
	}
	return NetworkingAvailability(SteamNetworkingSockets()->InitAuthentication());
}

// Query our readiness to participate in authenticated communications. A SteamNetAuthenticationStatus_t callback is posted any time this status changes, but you can use this function to query it at any time.
SteamServer::NetworkingAvailability SteamServer::getAuthenticationStatus(){
	if(SteamNetworkingSockets() == NULL){
		return NETWORKING_AVAILABILITY_UNKNOWN;
	}
	return NetworkingAvailability(SteamNetworkingSockets()->GetAuthenticationStatus(NULL));
}

// Call this when you receive a ticket from your backend / matchmaking system. Puts the ticket into a persistent cache, and optionally returns the parsed ticket.
//Dictionary SteamServer::receivedRelayAuthTicket(){
//	Dictionary ticket;
//	if(SteamNetworkingSockets() != NULL){
//		SteamDatagramRelayAuthTicket parsed_ticket;
//		PackedByteArray incoming_ticket;
//		incoming_ticket.resize(512);		
//		if(SteamNetworkingSockets()->ReceivedRelayAuthTicket(incoming_ticket.ptrw(), 512, &parsed_ticket)){
//			char game_server;
//			parsed_ticket.m_identityGameserver.ToString(&game_server, 128);
//			ticket["game_server"] = game_server;
//			char authorized_client;
//			parsed_ticket.m_identityAuthorizedClient.ToString(&authorized_client, 128);
//			ticket["authorized_client"] = authorized_client;
//			ticket["public_ip"] = parsed_ticket.m_unPublicIP;		// uint32
//			ticket["expiry"] = parsed_ticket.m_rtimeTicketExpiry;	// RTime32
//			ticket["routing"] = parsed_ticket.m_routing.GetPopID();			// SteamDatagramHostAddress
//			ticket["app_id"] = parsed_ticket.m_nAppID;				// uint32
//			ticket["restrict_to_v_port"] = parsed_ticket.m_nRestrictToVirtualPort;	// int
//			ticket["number_of_extras"] = parsed_ticket.m_nExtraFields;		// int
//			ticket["extra_fields"] = parsed_ticket.m_vecExtraFields;		// ExtraField
//		}
//	}
//	return ticket;
//}

// Search cache for a ticket to talk to the server on the specified virtual port. If found, returns the number of seconds until the ticket expires, and optionally the complete cracked ticket. Returns 0 if we don't have a ticket.
//int SteamServer::findRelayAuthTicketForServer(int port){
//	int expires_in_seconds = 0;
//	if(SteamNetworkingSockets() != NULL){
//		expires_in_seconds = SteamNetworkingSockets()->FindRelayAuthTicketForServer(game_server, port, &relay_auth_ticket);
//	}
//	return expires_in_seconds;
//}



// Returns the value of the SDR_LISTEN_PORT environment variable. This is the UDP server your server will be listening on. This will configured automatically for you in production environments.
uint16 SteamServer::getHostedDedicatedServerPort(){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	return SteamNetworkingSockets()->GetHostedDedicatedServerPort();
}

// Returns 0 if SDR_LISTEN_PORT is not set. Otherwise, returns the data center the server is running in. This will be k_SteamDatagramPOPID_dev in non-production envirionment.
uint32 SteamServer::getHostedDedicatedServerPOPId(){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	return SteamNetworkingSockets()->GetHostedDedicatedServerPOPID();
}

// Return info about the hosted server. This contains the PoPID of the server, and opaque routing information that can be used by the relays to send traffic to your server.
//int SteamServer::getHostedDedicatedServerAddress(){
//	int result = 2;
//	if(SteamNetworkingSockets() != NULL){
//		result = SteamNetworkingSockets()->GetHostedDedicatedServerAddress(&hosted_address);
//	}
//	return result;
//}

// Create a listen socket on the specified virtual port. The physical UDP port to use will be determined by the SDR_LISTEN_PORT environment variable. If a UDP port is not configured, this call will fail.
uint32 SteamServer::createHostedDedicatedServerListenSocket(int port, Array options){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	const SteamNetworkingConfigValue_t *these_options = convertOptionsArray(options);
	uint32 listen_socket = SteamGameServerNetworkingSockets()->CreateHostedDedicatedServerListenSocket(port, options.size(), these_options);
	delete[] these_options;
	return listen_socket;
}

// Generate an authentication blob that can be used to securely login with your backend, using SteamDatagram_ParseHostedServerLogin. (See steamdatagram_gamecoordinator.h)
//int SteamServer::getGameCoordinatorServerLogin(const String& app_data){
//	int result = 2;
//	if(SteamNetworkingSockets() != NULL){	
//		SteamDatagramGameCoordinatorServerLogin *server_login = new SteamDatagramGameCoordinatorServerLogin;
//		server_login->m_cbAppData = app_data.size();
//		strcpy(server_login->m_appData, app_data.utf8().get_data());
//		int signed_blob = k_cbMaxSteamDatagramGameCoordinatorServerLoginSerialized;
//		routing_blob.resize(signed_blob);
//		result = SteamNetworkingSockets()->GetGameCoordinatorServerLogin(server_login, &signed_blob, routing_blob.ptrw());
//		delete server_login;
//	}
//	return result;
//}

// Returns a small set of information about the real-time state of the connection and the queue status of each lane.
Dictionary SteamServer::getConnectionRealTimeStatus(uint32 connection, int lanes, bool get_status){
	// Create the dictionary for returning
	Dictionary real_time_status;
	if(SteamNetworkingSockets() != NULL){
		SteamNetConnectionRealTimeStatus_t this_status;
		SteamNetConnectionRealTimeLaneStatus_t *lanes_array = new SteamNetConnectionRealTimeLaneStatus_t[lanes];
		int result = SteamNetworkingSockets()->GetConnectionRealTimeStatus((HSteamNetConnection)connection, &this_status, lanes, lanes_array);
		// Append the status
		real_time_status["response"] = result;
		// If the result is good, get more data
		if(result == 0){
			// Get the connection status if requested
			Dictionary connection_status;
			if(get_status){
				connection_status["state"] = this_status.m_eState;
				connection_status["ping"] = this_status.m_nPing;
				connection_status["local_quality"] = this_status.m_flConnectionQualityLocal;
				connection_status["remote_quality"] = this_status.m_flConnectionQualityRemote;
				connection_status["packets_out_per_second"] = this_status.m_flOutPacketsPerSec;
				connection_status["bytes_out_per_second"] = this_status.m_flOutBytesPerSec;
				connection_status["packets_in_per_second"] = this_status.m_flInPacketsPerSec;
				connection_status["bytes_in_per_second"] = this_status.m_flInBytesPerSec;
				connection_status["send_rate"] = this_status.m_nSendRateBytesPerSecond;
				connection_status["pending_unreliable"] = this_status.m_cbPendingUnreliable;
				connection_status["pending_reliable"] = this_status.m_cbPendingReliable;
				connection_status["sent_unacknowledged_reliable"] = this_status.m_cbSentUnackedReliable;
				connection_status["queue_time"] = (uint64_t)this_status.m_usecQueueTime;
			}
			real_time_status["connection_status"] = connection_status;
			// Get the lane information
			Array lanes_status;
			for(int i = 0; i < lanes; i++){
				Dictionary lane_status;
				lane_status["pending_unreliable"] = lanes_array[i].m_cbPendingUnreliable;
				lane_status["pending_reliable"] = lanes_array[i].m_cbPendingReliable;
				lane_status["sent_unacknowledged_reliable"] = lanes_array[i].m_cbSentUnackedReliable;
				lane_status["queue_time"] = (uint64_t)lanes_array[i].m_usecQueueTime;
				lanes_status.append(lane_status);
			}
			delete[] lanes_array;
			real_time_status["lanes_status"] = lanes_status;
		}
	}
	return real_time_status;
}

// Configure multiple outbound messages streams ("lanes") on a connection, and control head-of-line blocking between them.
// Messages within a given lane are always sent in the order they are queued, but messages from different lanes may be sent out of order.
// Each lane has its own message number sequence.  The first message sent on each lane will be assigned the number 1.
int SteamServer::configureConnectionLanes(uint32 connection, int lanes, Array priorities, Array weights) {
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	// Convert the priorities array to an int
	int *lane_priorities = new int[lanes];
	for(int i = 0; i < lanes; i++){
		lane_priorities[i] = priorities[i];
	}
	// Convert the weights array to an int
	uint16 *lane_weights = new uint16[lanes];
	for(int i = 0; i < lanes; i++){
		// Horrendous solution to this issue of cannot convert Godot variant to uint16
		lane_weights[i] = int(weights[i]);
	}
	int result = SteamNetworkingSockets()->ConfigureConnectionLanes((HSteamNetConnection)connection, lanes, lane_priorities, lane_weights);
	delete[] lane_priorities;
	delete[] lane_weights;
	return result;
}


// Certificate provision by the application. On Steam, we normally handle all this automatically and you will not need to use these advanced functions.
Dictionary SteamServer::getCertificateRequest(){
	Dictionary cert_information;
	if(SteamNetworkingSockets() != NULL){
		int *certificate = new int[512];
		int cert_size = 0;
		SteamNetworkingErrMsg error_message;
		if(SteamNetworkingSockets()->GetCertificateRequest(&cert_size, &certificate, error_message)){
			cert_information["certificate"] = certificate;
			cert_information["cert_size"] = cert_size;
			cert_information["error_message"] = error_message;
		}
		delete[] certificate;
	}
	return cert_information;
}

// Set the certificate. The certificate blob should be the output of SteamDatagram_CreateCert.
Dictionary SteamServer::setCertificate(const PackedByteArray& certificate){
	Dictionary certificate_data;
	if(SteamNetworkingSockets() != NULL){
		bool success = false;
		SteamNetworkingErrMsg error_message;
		success = SteamNetworkingSockets()->SetCertificate((void*)certificate.ptr(), certificate.size(), error_message);
		if(success){
			certificate_data["response"] = success;
			certificate_data["error"] = error_message;
		}
	}
	return certificate_data;
}

// Reset the identity associated with this instance. Any open connections are closed.  Any previous certificates, etc are discarded.
// You can pass a specific identity that you want to use, or you can pass NULL, in which case the identity will be invalid until you set it using SetCertificate.
// NOTE: This function is not actually supported on Steam!  It is included for use on other platforms where the active user can sign out and a new user can sign in.
void SteamServer::resetIdentity(const String& identity_reference){
	if(SteamNetworkingSockets() != NULL){
		SteamNetworkingIdentity resetting_identity = networking_identities[identity_reference.utf8().get_data()];
		SteamNetworkingSockets()->ResetIdentity(&resetting_identity);
	}
}

// Invoke all callback functions queued for this interface. See k_ESteamNetworkingConfig_Callback_ConnectionStatusChanged, etc.
// You don't need to call this if you are using Steam's callback dispatch mechanism (SteamAPI_RunCallbacks and SteamGameserver_RunCallbacks).
void SteamServer::runNetworkingCallbacks(){
	if(SteamNetworkingSockets() != NULL){
		SteamNetworkingSockets()->RunCallbacks();		
	}
}

// Begin asynchronous process of allocating a fake IPv4 address that other peers can use to contact us via P2P.
// IP addresses returned by this function are globally unique for a given appid.
// Returns false if a request was already in progress, true if a new request was started.
// A SteamNetworkingFakeIPResult_t will be posted when the request completes.
bool SteamServer::beginAsyncRequestFakeIP(int num_ports){
	if(SteamNetworkingSockets() == NULL){
		return false;
	}
	return SteamNetworkingSockets()->BeginAsyncRequestFakeIP(num_ports);
}

// Return info about the FakeIP and port(s) that we have been assigned, if any.
// idxFirstPort is currently reserved and must be zero. Make sure and check SteamNetworkingFakeIPResult_t::m_eResult
Dictionary SteamServer::getFakeIP(int first_port){
	// Create the return dictionary
	Dictionary fake_ip;
	if(SteamNetworkingSockets() != NULL){
		SteamNetworkingFakeIPResult_t fake_ip_result;
		SteamNetworkingSockets()->GetFakeIP(first_port, &fake_ip_result);
		// Populate the dictionary
		fake_ip["result"] = fake_ip_result.m_eResult;
		fake_ip["identity_type"] = fake_ip_result.m_identity.m_eType;
		fake_ip["ip"] = fake_ip_result.m_unIP;
		char ports[8];
		for (size_t i = 0; i < sizeof(fake_ip_result.m_unPorts) / sizeof(fake_ip_result.m_unPorts[0]); i++){
			ports[i] = fake_ip_result.m_unPorts[i];
		}
		fake_ip["ports"] = ports;
	}
	return fake_ip;
}

// Create a listen socket that will listen for P2P connections sent to our FakeIP.
// A peer can initiate connections to this listen socket by calling ConnectByIPAddress.
uint32 SteamServer::createListenSocketP2PFakeIP(int fake_port, Array options){
	if(SteamNetworkingSockets() == NULL){
		return 0;
	}
	
	const SteamNetworkingConfigValue_t *these_options = convertOptionsArray(options);
	uint32 listen_socket = SteamNetworkingSockets()->CreateListenSocketP2PFakeIP(fake_port, options.size(), these_options);
	delete[] these_options;
	return listen_socket;
}

// If the connection was initiated using the "FakeIP" system, then we we can get an IP address for the remote host.  If the remote host had a global FakeIP at the time the connection was established, this function will return that global IP.
// Otherwise, a FakeIP that is unique locally will be allocated from the local FakeIP address space, and that will be returned.
Dictionary SteamServer::getRemoteFakeIPForConnection(uint32 connection){
	// Create the return dictionary
	Dictionary this_fake_address;
	if(SteamNetworkingSockets() != NULL){
		SteamNetworkingIPAddr fake_address;
		int result = SteamNetworkingSockets()->GetRemoteFakeIPForConnection((HSteamNetConnection)connection, &fake_address);
		// Send back the data
		this_fake_address["result"] = result;
		this_fake_address["port"] = fake_address.m_port;
		this_fake_address["ip_type"] = fake_address.GetFakeIPType();
		ip_addresses["fake_ip_address"] = fake_address;
		}

	return this_fake_address;
}

// Get an interface that can be used like a UDP port to send/receive datagrams to a FakeIP address.
// This is intended to make it easy to port existing UDP-based code to take advantage of SDR.
// To create a "client" port (e.g. the equivalent of an ephemeral UDP port) pass -1.
void SteamServer::createFakeUDPPort(int fake_server_port_index){
	if(SteamNetworkingSockets() != NULL){
		SteamNetworkingSockets()->CreateFakeUDPPort(fake_server_port_index);
	}
}


/////////////////////////////////////////////////
///// NETWORKING TYPES
/////////////////////////////////////////////////
//
// Create a new network identity and store it for use
bool SteamServer::addIdentity(const String& reference_name){
	networking_identities[reference_name.utf8().get_data()] = SteamNetworkingIdentity();
	if(networking_identities.count(reference_name.utf8().get_data()) > 0){
		return true;
	}
	return false;
}

// Clear a network identity's data
void SteamServer::clearIdentity(const String& reference_name){
	networking_identities[reference_name.utf8().get_data()].Clear();
}


// Get a list of all known network identities
Array SteamServer::getIdentities(){
	Array these_identities;
	// Loop through the map
	for(auto& identity : networking_identities){
		Dictionary this_identity;
		this_identity["reference_name"] = identity.first;
		this_identity["steam_id"] = (uint64_t)getIdentitySteamID64(identity.first);
		this_identity["type"] = networking_identities[identity.first].m_eType;
		these_identities.append(this_identity);
	}
	return these_identities;
}


// Return true if we are the invalid type.  Does not make any other validity checks (e.g. is SteamID actually valid)
bool SteamServer::isIdentityInvalid(const String& reference_name){
	return networking_identities[reference_name.utf8().get_data()].IsInvalid();
}

// Set a 32-bit Steam ID
void SteamServer::setIdentitySteamID(const String& reference_name, uint32 steam_id){
	networking_identities[reference_name.utf8().get_data()].SetSteamID(createSteamID(steam_id));
}

// Return CSteamID (!IsValid()) if identity is not a SteamID
uint32 SteamServer::getIdentitySteamID(const String& reference_name){
	CSteamID steam_id = networking_identities[reference_name.utf8().get_data()].GetSteamID();
	return steam_id.ConvertToUint64();
}

// Takes SteamID as raw 64-bit number
void SteamServer::setIdentitySteamID64(const String& reference_name, uint64_t steam_id){
	networking_identities[reference_name.utf8().get_data()].SetSteamID64(steam_id);
}

// Returns 0 if identity is not SteamID
uint64_t SteamServer::getIdentitySteamID64(const String& reference_name){
	return networking_identities[reference_name.utf8().get_data()].GetSteamID64();
}

// Set to specified IP:port.
bool SteamServer::setIdentityIPAddr(const String& reference_name, const String& ip_address_name){
	if(ip_addresses.count(ip_address_name.utf8().get_data()) > 0){
		const SteamNetworkingIPAddr this_address = ip_addresses[ip_address_name.utf8().get_data()];
		networking_identities[reference_name.utf8().get_data()].SetIPAddr(this_address);
		return true;
	}
	return false;
}

// Returns null if we are not an IP address.
uint32 SteamServer::getIdentityIPAddr(const String& reference_name){
	const SteamNetworkingIPAddr* this_address = networking_identities[reference_name.utf8().get_data()].GetIPAddr();
	if (this_address == NULL){
		return 0;
	}
	return this_address->GetIPv4();
}

// Retrieve this identity's Playstation Network ID.
uint64_t SteamServer::getPSNID(const String& reference_name){
	return networking_identities[reference_name.utf8().get_data()].GetPSNID();
}

// Retrieve this identity's Google Stadia ID.
uint64_t SteamServer::getStadiaID(const String& reference_name){
	return networking_identities[reference_name.utf8().get_data()].GetStadiaID();
}

// Retrieve this identity's XBox pair ID.
String SteamServer::getXboxPairwiseID(const String& reference_name){
	return networking_identities[reference_name.utf8().get_data()].GetXboxPairwiseID();
}

// Set to localhost. (We always use IPv6 ::1 for this, not 127.0.0.1).
void SteamServer::setIdentityLocalHost(const String& reference_name){
	networking_identities[reference_name.utf8().get_data()].SetLocalHost();
}

// Return true if this identity is localhost.
bool SteamServer::isIdentityLocalHost(const String& reference_name){
	return networking_identities[reference_name.utf8().get_data()].IsLocalHost();
}

// Returns false if invalid length.
bool SteamServer::setGenericString(const String& reference_name, const String& this_string){
	return networking_identities[reference_name.utf8().get_data()].SetGenericString(this_string.utf8().get_data());
}

// Returns nullptr if not generic string type
String SteamServer::getGenericString(const String& reference_name){
	return networking_identities[reference_name.utf8().get_data()].GetGenericString();
}

// Returns false if invalid size.
bool SteamServer::setGenericBytes(const String& reference_name, int data){
	const void *this_data = &data;
	return networking_identities[reference_name.utf8().get_data()].SetGenericBytes(this_data, sizeof(data));
}

// Returns null if not generic bytes type.
uint8 SteamServer::getGenericBytes(const String& reference_name){
	uint8 these_bytes = 0;
	if(!reference_name.is_empty()){
		int length = 0;
		const uint8* generic_bytes = networking_identities[reference_name.utf8().get_data()].GetGenericBytes(length);
		these_bytes = *generic_bytes;
	}
	return these_bytes;
}

// Add a new IP address struct
bool SteamServer::addIPAddress(const String& reference_name){
	ip_addresses[reference_name.utf8().get_data()] = SteamNetworkingIPAddr();
	if(ip_addresses.count(reference_name.utf8().get_data()) > 0){
		return true;
	}
	return false;
}

// Get a list of all IP address structs and their names
Array SteamServer::getIPAddresses(){
	Array these_addresses;
	// Loop through the map
	for(auto& address : ip_addresses){
		Dictionary this_address;
		this_address["reference_name"] = address.first;
		this_address["localhost"] = isAddressLocalHost(address.first);
		this_address["ip_address"] = getIPv4(address.first);
		these_addresses.append(this_address);
	}
	return these_addresses;
}

// IP Address - Set everything to zero. E.g. [::]:0
void SteamServer::clearIPAddress(const String& reference_name){
	ip_addresses[reference_name.utf8().get_data()].Clear();
}

// Return true if the IP is ::0. (Doesn't check port.)
bool SteamServer::isIPv6AllZeros(const String& reference_name){
	return ip_addresses[reference_name.utf8().get_data()].IsIPv6AllZeros();
}

// Set IPv6 address. IP is interpreted as bytes, so there are no endian issues. (Same as inaddr_in6.) The IP can be a mapped IPv4 address.
void SteamServer::setIPv6(const String& reference_name, int ipv6, int port){
	// For the love of glob, fix this
	uint8 messy_ipv6 = ipv6;
	const uint8 *this_ipv6 = &messy_ipv6;
	ip_addresses[reference_name.utf8().get_data()].SetIPv6(this_ipv6, port);
}

// Sets to IPv4 mapped address. IP and port are in host byte order.
void SteamServer::setIPv4(const String& reference_name, uint32 ip, int port){
	ip_addresses[reference_name.utf8().get_data()].SetIPv4(ip, (uint16)port);
}

// Return true if IP is mapped IPv4.
bool SteamServer::isIPv4(const String& reference_name){
	return ip_addresses[reference_name.utf8().get_data()].IsIPv4();
}

// Returns IP in host byte order (e.g. aa.bb.cc.dd as 0xaabbccdd). Returns 0 if IP is not mapped IPv4.
uint32 SteamServer::getIPv4(const String& reference_name){
	return ip_addresses[reference_name.utf8().get_data()].GetIPv4();
}

// Set to the IPv6 localhost address ::1, and the specified port.
void SteamServer::setIPv6LocalHost(const String& reference_name, int port){
	ip_addresses[reference_name.utf8().get_data()].SetIPv6LocalHost((uint16)port);
}

// Set the Playstation Network ID for this identity.
void SteamServer::setPSNID(const String& reference_name, uint64_t psn_id){
	networking_identities[reference_name.utf8().get_data()].SetPSNID(psn_id);
}

// Set the Google Stadia ID for this identity.
void SteamServer::setStadiaID(const String& reference_name, uint64_t stadia_id){
	networking_identities[reference_name.utf8().get_data()].SetStadiaID(stadia_id);
}

// Set the Xbox Pairwise ID for this identity.
bool SteamServer::setXboxPairwiseID(const String& reference_name, const String& xbox_id){
	return networking_identities[reference_name.utf8().get_data()].SetXboxPairwiseID(xbox_id.utf8().get_data());
}

// Return true if this identity is localhost. (Either IPv6 ::1, or IPv4 127.0.0.1).
bool SteamServer::isAddressLocalHost(const String& reference_name){
	return ip_addresses[reference_name.utf8().get_data()].IsLocalHost();
}

// Parse back a string that was generated using ToString. If we don't understand the string, but it looks "reasonable" (it matches the pattern type:<type-data> and doesn't have any funky characters, etc), then we will return true, and the type is set to k_ESteamNetworkingIdentityType_UnknownType.
// false will only be returned if the string looks invalid.
bool SteamServer::parseIdentityString(const String& reference_name, const String& string_to_parse){
	if(!reference_name.is_empty() && !string_to_parse.is_empty()){
		if(networking_identities[reference_name.utf8().get_data()].ParseString(string_to_parse.utf8().get_data())){
			return true;
		}
		return false;
	}
	return false;
}

// Parse an IP address and optional port.  If a port is not present, it is set to 0. (This means that you cannot tell if a zero port was explicitly specified.).
bool SteamServer::parseIPAddressString(const String& reference_name, const String& string_to_parse){
	if(!reference_name.is_empty() && !string_to_parse.is_empty()){
		if(ip_addresses[reference_name.utf8().get_data()].ParseString(string_to_parse.utf8().get_data())){
			return true;
		}
		return false;
	}
	return false;
}

// Print to a string, with or without the port. Mapped IPv4 addresses are printed as dotted decimal (12.34.56.78), otherwise this will print the canonical form according to RFC5952.
// If you include the port, IPv6 will be surrounded by brackets, e.g. [::1:2]:80. Your buffer should be at least k_cchMaxString bytes to avoid truncation.
String SteamServer::toIPAddressString(const String& reference_name, bool with_port){
	String ip_address_string = "";
	char *this_buffer = new char[128];
	ip_addresses[reference_name.utf8().get_data()].ToString(this_buffer, 128, with_port);
	ip_address_string = String(this_buffer);
	delete[] this_buffer;
	return ip_address_string;
}

// Print to a human-readable string.  This is suitable for debug messages or any other time you need to encode the identity as a string.
// It has a URL-like format (type:<type-data>). Your buffer should be at least k_cchMaxString bytes big to avoid truncation.
String SteamServer::toIdentityString(const String& reference_name){
	String identity_string = "";
	char *this_buffer = new char[128];
	networking_identities[reference_name.utf8().get_data()].ToString(this_buffer, 128);
	identity_string = String(this_buffer);
	delete[] this_buffer;
	return identity_string;
}

// Helper function to turn an array of options into an array of SteamNetworkingConfigValue_t structs
const SteamNetworkingConfigValue_t* SteamServer::convertOptionsArray(Array options){
	// Get the number of option arrays in the array.
	int options_size = options.size();
	// Create the array for options.
	SteamNetworkingConfigValue_t *option_array = new SteamNetworkingConfigValue_t[options_size];
	// If there are options
	if(options_size > 0){
		// Populate the options
		for(int i = 0; i < options_size; i++){
			SteamNetworkingConfigValue_t this_option;
			Array sent_option = options[i];
			// Get the configuration value.
			// This is a convoluted way of doing it but can't seem to cast the value as an enum so here we are.
			ESteamNetworkingConfigValue this_value = ESteamNetworkingConfigValue((int)sent_option[0]);
			if((int)sent_option[1] == 1){
				this_option.SetInt32(this_value, sent_option[2]);
			}
			else if((int)sent_option[1] == 2){
				this_option.SetInt64(this_value, sent_option[2]);
			}
			else if((int)sent_option[1] == 3){
				this_option.SetFloat(this_value, sent_option[2]);
			}
			else if((int)sent_option[1] == 4){
				char *this_string = { 0 };
				String passed_string = sent_option[2];
				strcpy(this_string, passed_string.utf8().get_data());
				this_option.SetString(this_value, this_string);
			}
			else{
				Object *this_pointer;
				this_pointer = sent_option[2];
				this_option.SetPtr(this_value, this_pointer);
			}
			option_array[i] = this_option;
		}
	}
	return option_array;
}


/////////////////////////////////////////////////
///// NETWORKING UTILS
/////////////////////////////////////////////////
//
// If you know that you are going to be using the relay network (for example, because you anticipate making P2P connections), call this to initialize the relay network. If you do not call this, the initialization will be delayed until the first time you use a feature that requires access to the relay network, which will delay that first access.
void SteamServer::initRelayNetworkAccess(){
	if(SteamNetworkingUtils() != NULL){
		SteamNetworkingUtils()->InitRelayNetworkAccess();
	}
}

// Fetch current status of the relay network.  If you want more details, you can pass a non-NULL value.
SteamServer::NetworkingAvailability SteamServer::getRelayNetworkStatus(){
	if(SteamNetworkingUtils() == NULL){
		return NETWORKING_AVAILABILITY_UNKNOWN;
	}
	return NetworkingAvailability(SteamNetworkingUtils()->GetRelayNetworkStatus(NULL));
}

// Return location info for the current host. Returns the approximate age of the data, in seconds, or -1 if no data is available.
Dictionary SteamServer::getLocalPingLocation(){
	Dictionary ping_location;
	if(SteamNetworkingUtils() != NULL){
		SteamNetworkPingLocation_t location;
		float age = SteamNetworkingUtils()->GetLocalPingLocation(location);
		// Populate the dictionary
		PackedByteArray data;
		data.resize(512);
		uint8_t* output_data = data.ptrw();
		for(int j = 0; j < 512; j++){
			output_data[j] = location.m_data[j];
		}
		ping_location["age"] = age;
		ping_location["location"] = data;
	}
	return ping_location;
}

// Estimate the round-trip latency between two arbitrary locations, in milliseconds. This is a conservative estimate, based on routing through the relay network. For most basic relayed connections, this ping time will be pretty accurate, since it will be based on the route likely to be actually used.
int SteamServer::estimatePingTimeBetweenTwoLocations(PackedByteArray location1, PackedByteArray location2){
	if(SteamNetworkingUtils() == NULL){
		return 0;
	}
	// Add these locations to ping structs
	SteamNetworkPingLocation_t ping_location1;
	SteamNetworkPingLocation_t ping_location2;
	uint8_t* input_location_1 = (uint8*) location1.ptr();
	for(int j = 0; j < 512; j++){
		ping_location1.m_data[j] = input_location_1[j];
	}
	uint8_t* input_location_2 = (uint8*) location2.ptr();
	for(int j = 0; j < 512; j++){
		ping_location2.m_data[j] = (uint8) input_location_2[j];
	}
	return SteamNetworkingUtils()->EstimatePingTimeBetweenTwoLocations(ping_location1, ping_location2);
}

// Same as EstimatePingTime, but assumes that one location is the local host. This is a bit faster, especially if you need to calculate a bunch of these in a loop to find the fastest one.
int SteamServer::estimatePingTimeFromLocalHost(PackedByteArray location){
	if(SteamNetworkingUtils() == NULL){
		return 0;
	}
	// Add this location to ping struct
	SteamNetworkPingLocation_t ping_location;
	uint8_t* input_location = (uint8*) location.ptr();
	for(int j = 0; j < 512; j++){
		ping_location.m_data[j] = input_location[j];
	}
	return SteamNetworkingUtils()->EstimatePingTimeFromLocalHost(ping_location);
}

// Convert a ping location into a text format suitable for sending over the wire. The format is a compact and human readable. However, it is subject to change so please do not parse it yourself. Your buffer must be at least k_cchMaxSteamNetworkingPingLocationString bytes.
String SteamServer::convertPingLocationToString(PackedByteArray location){
	String location_string = "";
	if(SteamNetworkingUtils() != NULL){
		char *buffer = new char[512];
		// Add this location to ping struct
		SteamNetworkPingLocation_t ping_location;
		uint8_t* input_location = (uint8*) location.ptr();
		for(int j = 0; j < 512; j++){
			ping_location.m_data[j] = input_location[j];
		}
		SteamNetworkingUtils()->ConvertPingLocationToString(ping_location, buffer, k_cchMaxSteamNetworkingPingLocationString);
		location_string += buffer;
		delete[] buffer;
	}
	return location_string;
}

// Parse back SteamNetworkPingLocation_t string. Returns false if we couldn't understand the string.
Dictionary SteamServer::parsePingLocationString(const String& location_string){
	Dictionary parse_string;
	if(SteamNetworkingUtils() != NULL){
		SteamNetworkPingLocation_t result;
		bool success = SteamNetworkingUtils()->ParsePingLocationString(location_string.utf8().get_data(), result);
		// Populate the dictionary
		PackedByteArray data;
		data.resize(512);
		uint8_t* output_data = data.ptrw();
		for(int j = 0; j < 512; j++){
			output_data[j] = result.m_data[j];
		}
		parse_string["success"] = success;
		parse_string["ping_location"] = data;
	}
	return parse_string;
}

// Check if the ping data of sufficient recency is available, and if it's too old, start refreshing it.
bool SteamServer::checkPingDataUpToDate(float max_age_in_seconds){
	if(SteamNetworkingUtils() == NULL){
		return false;
	}
	return SteamNetworkingUtils()->CheckPingDataUpToDate(max_age_in_seconds);
}

// Fetch ping time of best available relayed route from this host to the specified data center.
Dictionary SteamServer::getPingToDataCenter(uint32 pop_id){
	Dictionary data_center_ping;
	if(SteamNetworkingUtils() != NULL){
		SteamNetworkingPOPID via_relay_pop;
		int ping = SteamNetworkingUtils()->GetPingToDataCenter((SteamNetworkingPOPID)pop_id, &via_relay_pop);
		// Populate the dictionary
		data_center_ping["pop_relay"] = via_relay_pop;
		data_center_ping["ping"] = ping;
	}
	return data_center_ping;
}

// Get *direct* ping time to the relays at the point of presence.
int SteamServer::getDirectPingToPOP(uint32 pop_id){
	if(SteamNetworkingUtils() == NULL){
		return 0;
	}
	return SteamNetworkingUtils()->GetDirectPingToPOP((SteamNetworkingPOPID)pop_id);
}

// Get number of network points of presence in the config
int SteamServer::getPOPCount(){
	if(SteamNetworkingUtils() == NULL){
		return 0;
	}
	return SteamNetworkingUtils()->GetPOPCount();
}

// Get list of all POP IDs. Returns the number of entries that were filled into your list.
Array SteamServer::getPOPList(){
	Array pop_list;
	if(SteamNetworkingUtils() != NULL){
		SteamNetworkingPOPID *list = new SteamNetworkingPOPID[256];
		int pops = SteamNetworkingUtils()->GetPOPList(list, 256);
		// Iterate and add
		for(int i = 0; i < pops; i++){
			int pop_id = list[i];
			pop_list.append(pop_id);
		}
		delete[] list;
	}
	return pop_list;
}

// Set a configuration value.
//bool SteamServer::setConfigValue(int setting, int scope_type, uint32_t connection_handle, int data_type, auto value){
//	if(SteamNetworkingUtils() == NULL){
//		return false;
//	}
//	return SteamNetworkingUtils()->SetConfigValue((ESteamNetworkingConfigValue)setting, (ESteamNetworkingConfigScope)scope_type, connection_handle, (ESteamNetworkingConfigDataType)data_type, value);
//}

// Get a configuration value.
Dictionary SteamServer::getConfigValue(NetworkingConfigValue config_value, NetworkingConfigScope scope_type, uint32_t connection_handle){
	Dictionary config_info;
	if(SteamNetworkingUtils() != NULL){
		ESteamNetworkingConfigDataType data_type;
		size_t buffer_size;
		PackedByteArray config_result;
		int result = SteamNetworkingUtils()->GetConfigValue((ESteamNetworkingConfigValue)config_value, (ESteamNetworkingConfigScope)scope_type, connection_handle, &data_type, &config_result, &buffer_size);
		// Populate the dictionary
		config_info["result"] = result;
		config_info["type"] = data_type;
		config_info["value"] = config_result;
		config_info["buffer"] = (uint64_t)buffer_size;
	}
	return config_info;
}

// Returns info about a configuration value.
Dictionary SteamServer::getConfigValueInfo(NetworkingConfigValue config_value){
	Dictionary config_info;
	if(SteamNetworkingUtils() != NULL){
		ESteamNetworkingConfigDataType data_type;
		ESteamNetworkingConfigScope scope;
		if(SteamNetworkingUtils()->GetConfigValueInfo((ESteamNetworkingConfigValue)config_value, &data_type, &scope)){
			// Populate the dictionary
			config_info["type"] = data_type;
			config_info["scope"] = scope;
		}
	}
	return config_info;
}

// The following functions are handy shortcuts for common use cases.
bool SteamServer::setGlobalConfigValueInt32(NetworkingConfigValue config, int32 value){
	if(SteamNetworkingUtils() == NULL){
		return false;
	}
	return SteamNetworkingUtils()->SetGlobalConfigValueInt32((ESteamNetworkingConfigValue)config, value);
}
bool SteamServer::setGlobalConfigValueFloat(NetworkingConfigValue config, float value){
	if(SteamNetworkingUtils() == NULL){
		return false;
	}
	return SteamNetworkingUtils()->SetGlobalConfigValueFloat((ESteamNetworkingConfigValue)config, value);
}
bool SteamServer::setGlobalConfigValueString(NetworkingConfigValue config, const String& value){
	if(SteamNetworkingUtils() == NULL){
		return false;
	}
	return SteamNetworkingUtils()->SetGlobalConfigValueString((ESteamNetworkingConfigValue)config, value.utf8().get_data());
}
bool SteamServer::setConnectionConfigValueInt32(uint32 connection, NetworkingConfigValue config, int32 value){
	if(SteamNetworkingUtils() == NULL){
		return false;
	}
	return SteamNetworkingUtils()->SetConnectionConfigValueInt32(connection, (ESteamNetworkingConfigValue)config, value);
}
bool SteamServer::setConnectionConfigValueFloat(uint32 connection, NetworkingConfigValue config, float value){
	if(SteamNetworkingUtils() == NULL){
		return false;
	}
	return SteamNetworkingUtils()->SetConnectionConfigValueFloat(connection, (ESteamNetworkingConfigValue)config, value);
}

bool SteamServer::setConnectionConfigValueString(uint32 connection, NetworkingConfigValue config, const String& value){
	if(SteamNetworkingUtils() == NULL){
		return false;
	}
	return SteamNetworkingUtils()->SetConnectionConfigValueString(connection, (ESteamNetworkingConfigValue)config, value.utf8().get_data());
}

// A general purpose high resolution local timer with the following properties: Monotonicity is guaranteed. The initial value will be at least 24*3600*30*1e6, i.e. about 30 days worth of microseconds. In this way, the timestamp value of 0 will always be at least "30 days ago". Also, negative numbers will never be returned. Wraparound / overflow is not a practical concern.
uint64_t SteamServer::getLocalTimestamp(){
	if(SteamNetworkingUtils() == NULL){
		return 0;
	}
	return SteamNetworkingUtils()->GetLocalTimestamp();
}


/////////////////////////////////////////////////
///// UGC
/////////////////////////////////////////////////
//
// Adds a dependency between the given item and the appid. This list of dependencies can be retrieved by calling GetAppDependencies.
// This is a soft-dependency that is displayed on the web. It is up to the application to determine whether the item can actually be used or not.
void SteamServer::addAppDependency(uint64_t published_file_id, uint32_t app_id){
	if(SteamUGC() != NULL){
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		AppId_t app = (uint32_t)app_id;
		SteamAPICall_t api_call = SteamUGC()->AddAppDependency(file_id, app);
		callResultAddAppDependency.Set(api_call, this, &SteamServer::add_app_dependency_result);
	}
}

bool SteamServer::addContentDescriptor(uint64_t update_handle, int descriptor_id){
	if(SteamUGC() == NULL){
		return false;
	}
	return SteamUGC()->AddContentDescriptor((UGCUpdateHandle_t)update_handle, (EUGCContentDescriptorID)descriptor_id);
}

// Adds a workshop item as a dependency to the specified item. If the nParentPublishedFileID item is of type k_EWorkshopFileTypeCollection, than the nChildPublishedFileID is simply added to that collection.
// Otherwise, the dependency is a soft one that is displayed on the web and can be retrieved via the ISteamUGC API using a combination of the m_unNumChildren member variable of the SteamUGCDetails_t struct and GetQueryUGCChildren.
void SteamServer::addDependency(uint64_t published_file_id, uint64_t child_published_file_id){
	if(SteamUGC() != NULL){
		PublishedFileId_t parent = (uint64_t)published_file_id;
		PublishedFileId_t child = (uint64_t)child_published_file_id;
		SteamAPICall_t api_call = SteamUGC()->AddDependency(parent, child);
		callResultAddUGCDependency.Set(api_call, this, &SteamServer::add_ugc_dependency_result);
	}
}

// Adds a excluded tag to a pending UGC Query. This will only return UGC without the specified tag.
bool SteamServer::addExcludedTag(uint64_t query_handle, const String& tag_name){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->AddExcludedTag(handle, tag_name.utf8().get_data());
}

// Adds a key-value tag pair to an item. Keys can map to multiple different values (1-to-many relationship).
bool SteamServer::addItemKeyValueTag(uint64_t update_handle, const String& key, const String& value){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = (uint64_t)update_handle;
	return SteamUGC()->AddItemKeyValueTag(handle, key.utf8().get_data(), value.utf8().get_data());
}

// Adds an additional preview file for the item.
bool SteamServer::addItemPreviewFile(uint64_t query_handle, const String& preview_file, ItemPreviewType type){
	if(SteamUGC() == NULL){
		return false;
	}
	EItemPreviewType previewType;
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	if(type == 0){
		previewType = k_EItemPreviewType_Image;
	}
	else if(type == 1){
		previewType = k_EItemPreviewType_YouTubeVideo;
	}
	else if(type == 2){
		previewType = k_EItemPreviewType_Sketchfab;
	}
	else if(type == 3){
		previewType = k_EItemPreviewType_EnvironmentMap_HorizontalCross;
	}
	else if(type == 4){
		previewType = k_EItemPreviewType_EnvironmentMap_LatLong;
	}
	else{
		previewType = k_EItemPreviewType_ReservedMax;
	}
	return SteamUGC()->AddItemPreviewFile(handle, preview_file.utf8().get_data(), previewType);
}

// Adds an additional video preview from YouTube for the item.
bool SteamServer::addItemPreviewVideo(uint64_t query_handle, const String& video_id){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->AddItemPreviewVideo(handle, video_id.utf8().get_data());
}

// Adds a workshop item to the users favorites list.
void SteamServer::addItemToFavorites(uint32_t app_id, uint64_t published_file_id){
	if(SteamUGC() != NULL){
		AppId_t app = (uint32_t)app_id;
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		SteamAPICall_t api_call = SteamUGC()->AddItemToFavorites(app, file_id);
		callResultFavoriteItemListChanged.Set(api_call, this, &SteamServer::user_favorite_items_list_changed);
	}
}

// Adds a required key-value tag to a pending UGC Query. This will only return workshop items that have a key = pKey and a value = pValue.
bool SteamServer::addRequiredKeyValueTag(uint64_t query_handle, const String& key, const String& value){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->AddRequiredKeyValueTag(handle, key.utf8().get_data(), value.utf8().get_data());
}

// Adds a required tag to a pending UGC Query. This will only return UGC with the specified tag.
bool SteamServer::addRequiredTag(uint64_t query_handle, const String& tag_name){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->AddRequiredTag(handle, tag_name.utf8().get_data());
}

// Adds the requirement that the returned items from the pending UGC Query have at least one of the tags in the given set (logical "or"). For each tag group that is added, at least one tag from each group is required to be on the matching items.
bool SteamServer::addRequiredTagGroup(uint64_t query_handle, Array tag_array){
	bool added_tag_group = false;
	if(SteamUGC() != NULL){
		UGCQueryHandle_t handle = uint64(query_handle);
		SteamParamStringArray_t *tags = new SteamParamStringArray_t();
		tags->m_ppStrings = new const char*[tag_array.size()];
		uint32 strCount = tag_array.size();
		for (uint32 i=0; i < strCount; i++) {
			String str = (String)tag_array[i];
			tags->m_ppStrings[i] = str.utf8().get_data();
		}
		tags->m_nNumStrings = tag_array.size();
		added_tag_group = SteamUGC()->AddRequiredTagGroup(handle, tags);
		delete tags;
	}
	return added_tag_group;
}

// Lets game servers set a specific workshop folder before issuing any UGC commands.
bool SteamServer::initWorkshopForGameServer(uint32_t workshop_depot_id){
	bool initialized_workshop = false;
	if(SteamUGC() != NULL){
		DepotId_t workshop = (uint32_t)workshop_depot_id;
		const char *folder = new char[256];
		initialized_workshop = SteamUGC()->BInitWorkshopForGameServer(workshop, (char*)folder);
		delete[] folder;
	}
	return initialized_workshop;
}

// Creates a new workshop item with no content attached yet.
void SteamServer::createItem(uint32 app_id, WorkshopFileType file_type){
	if(SteamUGC() != NULL){
		SteamAPICall_t api_call = SteamUGC()->CreateItem((AppId_t)app_id, (EWorkshopFileType)file_type);
		callResultItemCreate.Set(api_call, this, &SteamServer::item_created);
	}
}

// Query for all matching UGC. You can use this to list all of the available UGC for your app.
uint64_t SteamServer::createQueryAllUGCRequest(UGCQuery query_type, UGCMatchingUGCType matching_type, uint32_t creator_id, uint32_t consumer_id, uint32 page){
	if(SteamUGC() == NULL){
		return 0;
	}
	EUGCQuery query;
	if(query_type == 0){
		query = k_EUGCQuery_RankedByVote;
	}
	else if(query_type == 1){
		query = k_EUGCQuery_RankedByPublicationDate;
	}
	else if(query_type == 2){
		query = k_EUGCQuery_AcceptedForGameRankedByAcceptanceDate;
	}
	else if(query_type == 3){
		query = k_EUGCQuery_RankedByTrend;
	}
	else if(query_type == 4){
		query = k_EUGCQuery_FavoritedByFriendsRankedByPublicationDate;
	}
	else if(query_type == 5){
		query = k_EUGCQuery_CreatedByFriendsRankedByPublicationDate;
	}
	else if(query_type == 6){
		query = k_EUGCQuery_RankedByNumTimesReported;
	}
	else if(query_type == 7){
		query = k_EUGCQuery_CreatedByFollowedUsersRankedByPublicationDate;
	}
	else if(query_type == 8){
		query = k_EUGCQuery_NotYetRated;
	}
	else if(query_type == 9){
		query = k_EUGCQuery_RankedByTotalVotesAsc;
	}
	else if(query_type == 10){
		query = k_EUGCQuery_RankedByVotesUp;
	}
	else if(query_type == 11){
		query = k_EUGCQuery_RankedByTextSearch;
	}
	else if(query_type == 12){
		query = k_EUGCQuery_RankedByTotalUniqueSubscriptions;
	}
	else if(query_type == 13){
		query = k_EUGCQuery_RankedByPlaytimeTrend;
	}
	else if(query_type == 14){
		query = k_EUGCQuery_RankedByTotalPlaytime;
	}
	else if(query_type == 15){
		query = k_EUGCQuery_RankedByAveragePlaytimeTrend;
	}
	else if(query_type == 16){
		query = k_EUGCQuery_RankedByLifetimeAveragePlaytime;
	}
	else if(query_type == 17){
		query = k_EUGCQuery_RankedByPlaytimeSessionsTrend;
	}
	else{
		query = k_EUGCQuery_RankedByLifetimePlaytimeSessions;
	}
	EUGCMatchingUGCType match;
	if(matching_type == 0){
		match = k_EUGCMatchingUGCType_All;
	}
	else if(matching_type == 1){
		match = k_EUGCMatchingUGCType_Items_Mtx;
	}
	else if(matching_type == 2){
		match = k_EUGCMatchingUGCType_Items_ReadyToUse;
	}
	else if(matching_type == 3){
		match = k_EUGCMatchingUGCType_Collections;
	}
	else if(matching_type == 4){
		match = k_EUGCMatchingUGCType_Artwork;
	}
	else if(matching_type == 5){
		match = k_EUGCMatchingUGCType_Videos;
	}
	else if(matching_type == 6){
		match = k_EUGCMatchingUGCType_Screenshots;
	}
	else if(matching_type == 7){
		match = k_EUGCMatchingUGCType_AllGuides;
	}
	else if(matching_type == 8){
		match = k_EUGCMatchingUGCType_WebGuides;
	}
	else if(matching_type == 9){
		match = k_EUGCMatchingUGCType_IntegratedGuides;
	}
	else if(matching_type == 10){
		match = k_EUGCMatchingUGCType_UsableInGame;
	}
	else if(matching_type == 11){
		match = k_EUGCMatchingUGCType_ControllerBindings;
	}
	else{
		match = k_EUGCMatchingUGCType_GameManagedItems;
	}
	AppId_t creator = (uint32_t)creator_id;
	AppId_t consumer = (uint32_t)consumer_id;
	UGCQueryHandle_t handle = SteamUGC()->CreateQueryAllUGCRequest(query, match, creator, consumer, page);
	return (uint64_t)handle;
}

// Query for the details of specific workshop items.
uint64_t SteamServer::createQueryUGCDetailsRequest(Array published_file_ids){
	uint64_t this_handle = 0;
	if(SteamUGC() != NULL){
		uint32 fileCount = published_file_ids.size();
		if(fileCount != 0){
			PublishedFileId_t *file_ids = new PublishedFileId_t[fileCount];
			for(uint32 i = 0; i < fileCount; i++){
				file_ids[i] = (uint64_t)published_file_ids[i];
			}
			UGCQueryHandle_t handle = SteamUGC()->CreateQueryUGCDetailsRequest(file_ids, fileCount);
			delete[] file_ids;
			this_handle = (uint64_t)handle;
		}
	}
	return this_handle;
}

// Query UGC associated with a user. You can use this to list the UGC the user is subscribed to amongst other things.
uint64_t SteamServer::createQueryUserUGCRequest(uint64_t steam_id, UserUGCList list_type, UGCMatchingUGCType matching_ugc_type, UserUGCListSortOrder sort_order, uint32_t creator_id, uint32_t consumer_id, uint32 page){
	if(SteamUGC() == NULL){
		return 0;
	}
	// Get tue universe ID from the Steam ID
	CSteamID user_id = (uint64)steam_id;
	AccountID_t account = (AccountID_t)user_id.ConvertToUint64();
	EUserUGCList list;
	if(list_type == 0){
		list = k_EUserUGCList_Published;
	}
	else if(list_type == 1){
		list = k_EUserUGCList_VotedOn;
	}
	else if(list_type == 2){
		list = k_EUserUGCList_VotedUp;
	}
	else if(list_type == 3){
		list = k_EUserUGCList_VotedDown;
	}
	else if(list_type == 4){
		list = k_EUserUGCList_WillVoteLater;
	}
	else if(list_type == 5){
		list = k_EUserUGCList_Favorited;
	}
	else if(list_type == 6){
		list = k_EUserUGCList_Subscribed;
	}
	else if(list_type == 7){
		list = k_EUserUGCList_UsedOrPlayed;
	}
	else{
		list = k_EUserUGCList_Followed;
	}
	EUGCMatchingUGCType match;
	if(matching_ugc_type == 0){
		match = k_EUGCMatchingUGCType_All;
	}
	else if(matching_ugc_type == 1){
		match = k_EUGCMatchingUGCType_Items_Mtx;
	}
	else if(matching_ugc_type == 2){
		match = k_EUGCMatchingUGCType_Items_ReadyToUse;
	}
	else if(matching_ugc_type == 3){
		match = k_EUGCMatchingUGCType_Collections;
	}
	else if(matching_ugc_type == 4){
		match = k_EUGCMatchingUGCType_Artwork;
	}
	else if(matching_ugc_type == 5){
		match = k_EUGCMatchingUGCType_Videos;
	}
	else if(matching_ugc_type == 6){
		match = k_EUGCMatchingUGCType_Screenshots;
	}
	else if(matching_ugc_type == 7){
		match = k_EUGCMatchingUGCType_AllGuides;
	}
	else if(matching_ugc_type == 8){
		match = k_EUGCMatchingUGCType_WebGuides;
	}
	else if(matching_ugc_type == 9){
		match = k_EUGCMatchingUGCType_IntegratedGuides;
	}
	else if(matching_ugc_type == 10){
		match = k_EUGCMatchingUGCType_UsableInGame;
	}
	else if(matching_ugc_type == 11){
		match = k_EUGCMatchingUGCType_ControllerBindings;
	}
	else{
		match = k_EUGCMatchingUGCType_GameManagedItems;
	}
	EUserUGCListSortOrder sort;
	if(sort_order == 0){
		sort = k_EUserUGCListSortOrder_CreationOrderDesc;
	}
	else if(sort_order == 1){
		sort = k_EUserUGCListSortOrder_CreationOrderAsc;
	}
	else if(sort_order == 2){
		sort = k_EUserUGCListSortOrder_TitleAsc;
	}
	else if(sort_order == 3){
		sort = k_EUserUGCListSortOrder_LastUpdatedDesc;
	}
	else if(sort_order == 4){
		sort = k_EUserUGCListSortOrder_SubscriptionDateDesc;
	}
	else if(sort_order == 5){
		sort = k_EUserUGCListSortOrder_VoteScoreDesc;
	}
	else{
		sort = k_EUserUGCListSortOrder_ForModeration;
	}
	AppId_t creator = (int)creator_id;
	AppId_t consumer = (int)consumer_id;
	UGCQueryHandle_t handle = SteamUGC()->CreateQueryUserUGCRequest(account, list, match, sort, creator, consumer, page);
	return (uint64_t)handle;
}

// Deletes the item without prompting the user.
void SteamServer::deleteItem(uint64_t published_file_id){
	if(SteamUGC() != NULL){
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		SteamAPICall_t api_call = SteamUGC()->DeleteItem(file_id);
		callResultDeleteItem.Set(api_call, this, &SteamServer::item_deleted);
	}
}

// Download new or update already installed item. If returns true, wait for DownloadItemResult_t. If item is already installed, then files on disk should not be used until callback received.
// If item is not subscribed to, it will be cached for some time. If bHighPriority is set, any other item download will be suspended and this item downloaded ASAP.
bool SteamServer::downloadItem(uint64_t published_file_id, bool high_priority){
	if(SteamUGC() == NULL){
		return false;
	}
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	return SteamUGC()->DownloadItem(file_id, high_priority);
}

// Get info about a pending download of a workshop item that has k_EItemStateNeedsUpdate set.
Dictionary SteamServer::getItemDownloadInfo(uint64_t published_file_id){
	Dictionary info;
	if(SteamUGC() == NULL){
		return info;
	}
	uint64 downloaded = 0;
	uint64 total = 0;
	info["ret"] = SteamUGC()->GetItemDownloadInfo((PublishedFileId_t)published_file_id, &downloaded, &total);
	if(info["ret"]){
		info["downloaded"] = uint64_t(downloaded);
		info["total"] = uint64_t(total);
	}
	return info;
}

// Gets info about currently installed content on the disc for workshop items that have k_EItemStateInstalled set.
Dictionary SteamServer::getItemInstallInfo(uint64_t published_file_id){
	Dictionary info;
	if(SteamUGC() == NULL){
		info["ret"] = false;
		return info;
	}
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	uint64 sizeOnDisk;
	char folder[1024] = { 0 };
	uint32 timeStamp;
	info["ret"] = SteamUGC()->GetItemInstallInfo((PublishedFileId_t)file_id, &sizeOnDisk, folder, sizeof(folder), &timeStamp);
	if(info["ret"]){
		info["size"] = (int)sizeOnDisk;
		info["folder"] = folder;
		info["foldersize"] = (uint32)sizeof(folder);
		info["timestamp"] = timeStamp;
	}
	return info;
}

// Gets the current state of a workshop item on this client.
uint32 SteamServer::getItemState(uint64_t published_file_id){
	if(SteamUGC() == NULL){
		return 0;
	}
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	return SteamUGC()->GetItemState(file_id);
}

// Gets the progress of an item update.
Dictionary SteamServer::getItemUpdateProgress(uint64_t update_handle){
	Dictionary updateProgress;
	if(SteamUGC() == NULL){
		return updateProgress;
	}
	UGCUpdateHandle_t handle = (uint64_t)update_handle;
	uint64 processed = 0;
	uint64 total = 0;
	EItemUpdateStatus status = SteamUGC()->GetItemUpdateProgress(handle, &processed, &total);
	updateProgress["status"] = status;
	updateProgress["processed"] = uint64_t(processed);
	updateProgress["total"] = uint64_t(total);
	return updateProgress;
}

// Gets the total number of items the current user is subscribed to for the game or application.
uint32 SteamServer::getNumSubscribedItems(){
	if(SteamUser() == NULL){
		return 0;
	}
	return SteamUGC()->GetNumSubscribedItems();
}

// Retrieve the details of an additional preview associated with an individual workshop item after receiving a querying UGC call result.
Dictionary SteamServer::getQueryUGCAdditionalPreview(uint64_t query_handle, uint32 index, uint32 preview_index){
	Dictionary preview;
	if(SteamUGC() == NULL){
		return preview;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	char *url_or_video_id = new char[256];
	char *original_filename = new char[256];
	EItemPreviewType previewType;
	bool success = SteamUGC()->GetQueryUGCAdditionalPreview(handle, index, preview_index, (char*)url_or_video_id, 256, (char*)original_filename, 256, &previewType);
	if(success){
		preview["success"] = success;
		preview["handle"] = (uint64_t)handle;
		preview["index"] = index;
		preview["preview"] = preview_index;
		preview["urlOrVideo"] = url_or_video_id;
		preview["filename"] = original_filename;
		preview["type"] = previewType;
	}
	delete[] url_or_video_id;
	delete[] original_filename;
	return preview;
}

// Retrieve the ids of any child items of an individual workshop item after receiving a querying UGC call result. These items can either be a part of a collection or some other dependency (see AddDependency).
Dictionary SteamServer::getQueryUGCChildren(uint64_t query_handle, uint32 index, uint32_t child_count){
	Dictionary children;
	if(SteamUGC() == NULL){
		return children;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	PackedVector2Array vec;
	vec.resize(child_count);
	bool success = SteamUGC()->GetQueryUGCChildren(handle, index, (PublishedFileId_t*)vec.ptrw(), child_count);
	if(success) {
		Array godot_arr;
		godot_arr.resize(child_count);
		for (uint32_t i = 0; i < child_count; i++) {
			godot_arr[i] = vec[i];
		}
		
		children["success"] = success;
		children["handle"] = (uint64_t)handle;
		children["index"] = index;
		children["children"] = godot_arr;
	}
	return children;
}

Dictionary SteamServer::getQueryUGCContentDescriptors(uint64_t query_handle, uint32 index, uint32_t max_entries){
	Dictionary descriptors;
	if(SteamUGC() != NULL){
		UGCQueryHandle_t handle = (uint64_t)query_handle;
		PackedVector2Array vec;
		vec.resize(max_entries);
		uint32_t result = SteamUGC()->GetQueryUGCContentDescriptors(handle, index, (EUGCContentDescriptorID*)vec.ptrw(), max_entries);
		Array descriptor_array;
		descriptor_array.resize(max_entries);
		for(uint32_t i = 0; i < max_entries; i++){
			descriptor_array[i] = vec[i];
		}
		descriptors["result"] = result;
		descriptors["handle"] = (uint64_t)handle;
		descriptors["index"] = index;
		descriptors["descriptors"] = descriptor_array;
	}
	return descriptors;
}

// Retrieve the details of a key-value tag associated with an individual workshop item after receiving a querying UGC call result.
Dictionary SteamServer::getQueryUGCKeyValueTag(uint64_t query_handle, uint32 index, uint32 key_value_tag_index){
	Dictionary tag;
	if(SteamUGC() == NULL){
		return tag;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	char *key = new char[256];
	char *value = new char[256];
	bool success = SteamUGC()->GetQueryUGCKeyValueTag(handle, index, key_value_tag_index, (char*)key, 256, (char*)value, 256);
	if(success){
		tag["success"] = success;
		tag["handle"] = (uint64_t)handle;
		tag["index"] = index;
		tag["tag"] = key_value_tag_index;
		tag["key"] = key;
		tag["value"] = value;
	}
	delete[] key;
	delete[] value;
	return tag;
}

// Retrieve the developer set metadata of an individual workshop item after receiving a querying UGC call result.
String SteamServer::getQueryUGCMetadata(uint64_t query_handle, uint32 index){
	String query_ugc_metadata = "";
	if(SteamUGC() != NULL){
		UGCQueryHandle_t handle = (uint64_t)query_handle;
		char *ugc_metadata = new char[5000];
		bool success = SteamUGC()->GetQueryUGCMetadata(handle, index, (char*)ugc_metadata, 5000);
		if(success){
			query_ugc_metadata = ugc_metadata;
		}
		delete[] ugc_metadata;
	}
	return query_ugc_metadata;
}

// Retrieve the number of additional previews of an individual workshop item after receiving a querying UGC call result.
uint32 SteamServer::getQueryUGCNumAdditionalPreviews(uint64_t query_handle, uint32 index){
	if(SteamUser() == NULL){
		return 0;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->GetQueryUGCNumAdditionalPreviews(handle, index);
}

// Retrieve the number of key-value tags of an individual workshop item after receiving a querying UGC call result.
uint32 SteamServer::getQueryUGCNumKeyValueTags(uint64_t query_handle, uint32 index){
	if(SteamUser() == NULL){
		return 0;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->GetQueryUGCNumKeyValueTags(handle, index);
}

// Retrieve the number of tags for an individual workshop item after receiving a querying UGC call result. You should call this in a loop to get the details of all the workshop items returned.
uint32 SteamServer::getQueryUGCNumTags(uint64_t query_handle, uint32 index){
	if(SteamUGC() == NULL){
		return 0;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->GetQueryUGCNumTags(handle, index);
}

// Retrieve the URL to the preview image of an individual workshop item after receiving a querying UGC call result.
String SteamServer::getQueryUGCPreviewURL(uint64_t query_handle, uint32 index){
	String query_ugc_preview_url = "";
	if(SteamUGC() != NULL){
		UGCQueryHandle_t handle = (uint64_t)query_handle;
		char *url = new char[256];
		bool success = SteamUGC()->GetQueryUGCPreviewURL(handle, index, (char*)url, 256);
		if(success){
			query_ugc_preview_url = url;
		}
		delete[] url;
	}
	return query_ugc_preview_url;
}

// Retrieve the details of an individual workshop item after receiving a querying UGC call result.
Dictionary SteamServer::getQueryUGCResult(uint64_t query_handle, uint32 index){
	Dictionary ugcResult;
	if(SteamUGC() == NULL){
		return ugcResult;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	SteamUGCDetails_t pDetails;
	bool success = SteamUGC()->GetQueryUGCResult(handle, index, &pDetails);
	if(success){
		ugcResult["result"] = (uint64_t)pDetails.m_eResult;
		ugcResult["file_id"] = (uint64_t)pDetails.m_nPublishedFileId;
		ugcResult["file_type"] = (uint64_t)pDetails.m_eFileType;
		ugcResult["creator_app_id"] = (uint32_t)pDetails.m_nCreatorAppID;
		ugcResult["consumer_app_id"] = (uint32_t)pDetails.m_nConsumerAppID;
		ugcResult["title"] = String::utf8(pDetails.m_rgchTitle);
		ugcResult["description"] = String::utf8(pDetails.m_rgchDescription);
		ugcResult["steam_id_owner"] = (uint64_t)pDetails.m_ulSteamIDOwner;
		ugcResult["time_created"] = pDetails.m_rtimeCreated;
		ugcResult["time_updated"] = pDetails.m_rtimeUpdated;
		ugcResult["time_added_to_user_list"] = pDetails.m_rtimeAddedToUserList;
		ugcResult["visibility"] = (uint64_t)pDetails.m_eVisibility;
		ugcResult["banned"] = pDetails.m_bBanned;
		ugcResult["accepted_for_use"] = pDetails.m_bAcceptedForUse;
		ugcResult["tags_truncated"] = pDetails.m_bTagsTruncated;
		ugcResult["tags"] = pDetails.m_rgchTags;
		ugcResult["handle_file"] = (uint64_t)pDetails.m_hFile;
		ugcResult["handle_preview_file"] = (uint64_t)pDetails.m_hPreviewFile;
		ugcResult["file_name"] = pDetails.m_pchFileName;
		ugcResult["file_size"] = pDetails.m_nFileSize;
		ugcResult["preview_file_size"] = pDetails.m_nPreviewFileSize;
		ugcResult["url"] = pDetails.m_rgchURL;
		ugcResult["votes_up"] = pDetails.m_unVotesUp;
		ugcResult["votes_down"] = pDetails.m_unVotesDown;
		ugcResult["score"] = pDetails.m_flScore;
		ugcResult["num_children"] = pDetails.m_unNumChildren;
	}
	return ugcResult;
}

// Retrieve various statistics of an individual workshop item after receiving a querying UGC call result.
Dictionary SteamServer::getQueryUGCStatistic(uint64_t query_handle, uint32 index, ItemStatistic stat_type){
	Dictionary ugcStat;
	if(SteamUGC() == NULL){
		return ugcStat;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	EItemStatistic type;
		if(stat_type == 0){
		type = k_EItemStatistic_NumSubscriptions;
	}
	else if(stat_type == 1){
		type = k_EItemStatistic_NumFavorites;
	}
	else if(stat_type == 2){
		type = k_EItemStatistic_NumFollowers;
	}
	else if(stat_type == 3){
		type = k_EItemStatistic_NumUniqueSubscriptions;
	}
	else if(stat_type == 4){
		type = k_EItemStatistic_NumUniqueFavorites;
	}
	else if(stat_type == 5){
		type = k_EItemStatistic_NumUniqueFollowers;
	}
	else if(stat_type == 6){
		type = k_EItemStatistic_NumUniqueWebsiteViews;
	}
	else if(stat_type == 7){
		type = k_EItemStatistic_ReportScore;
	}
	else if(stat_type == 8){
		type = k_EItemStatistic_NumSecondsPlayed;
	}
	else if(stat_type == 9){
		type = k_EItemStatistic_NumPlaytimeSessions;
	}
	else if(stat_type == 10){
		type = k_EItemStatistic_NumComments;
	}
	else if(stat_type == 11){
		type = k_EItemStatistic_NumSecondsPlayedDuringTimePeriod;
	}
	else{
		type = k_EItemStatistic_NumPlaytimeSessionsDuringTimePeriod;
	}
	uint64 value = 0;
	bool success = SteamUGC()->GetQueryUGCStatistic(handle, index, type, &value);
	if(success){
		ugcStat["success"] = success;
		ugcStat["handle"] = (uint64_t)handle;
		ugcStat["index"] = index;
		ugcStat["type"] = type;
		ugcStat["value"] = (uint64_t)value;
	}	
	return ugcStat;
}

// Retrieve the "nth" tag associated with an individual workshop item after receiving a querying UGC call result.
// You should call this in a loop to get the details of all the workshop items returned.
String SteamServer::getQueryUGCTag(uint64_t query_handle, uint32 index, uint32 tag_index){
	if(SteamUGC() == NULL){
		return "";
	}
	// Set a default tag to return
	char *tag = new char[64];
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	SteamUGC()->GetQueryUGCTag(handle, index, tag_index, tag, 64);
	tag[63] = '\0';
	String tag_name = tag;
	delete[] tag;
	return tag_name;
}

// Retrieve the "nth" display string (usually localized) for a tag, which is associated with an individual workshop item after receiving a querying UGC call result.
// You should call this in a loop to get the details of all the workshop items returned.
String SteamServer::getQueryUGCTagDisplayName(uint64_t query_handle, uint32 index, uint32 tag_index){
	if(SteamUGC() == NULL){
		return "";
	}
	// Set a default tag name to return
	char *tag = new char[256];
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	SteamUGC()->GetQueryUGCTagDisplayName(handle, index, tag_index, tag, 256);
	tag[255] = '\0';
	String tagDisplay = tag;
	delete[] tag;
	return tagDisplay;
}

// Gets a list of all of the items the current user is subscribed to for the current game.
Array SteamServer::getSubscribedItems(){
	if(SteamUGC() == NULL){
		return Array();
	}
	Array subscribed;
	uint32 num_items = SteamUGC()->GetNumSubscribedItems();
	PublishedFileId_t *items = new PublishedFileId_t[num_items];
	uint32 item_list = SteamUGC()->GetSubscribedItems(items, num_items);
	for(uint32 i = 0; i < item_list; i++){
		subscribed.append((uint64_t)items[i]);
	}
	delete[] items;
	return subscribed;
}

// Return the user's community content descriptor preferences
// Information is unclear how this actually works so here goes nothing!
Array SteamServer::getUserContentDescriptorPreferences(uint32 max_entries){
	Array descriptors;
	if(SteamUGC() != NULL){
		EUGCContentDescriptorID *descriptor_list = new EUGCContentDescriptorID[max_entries];
		uint32 num_descriptors = SteamUGC()->GetUserContentDescriptorPreferences(descriptor_list, max_entries);
		for(uint32 i = 0; i < num_descriptors; i++){
			descriptors.append(descriptor_list[i]);
		}
	}
	return descriptors;
}

// Gets the users vote status on a workshop item.
void SteamServer::getUserItemVote(uint64_t published_file_id){
	if(SteamUGC() != NULL){
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		SteamAPICall_t api_call = SteamUGC()->GetUserItemVote(file_id);
		callResultGetUserItemVote.Set(api_call, this, &SteamServer::get_item_vote_result);
	}
}

// Releases a UGC query handle when you are done with it to free up memory.
bool SteamServer::releaseQueryUGCRequest(uint64_t query_handle){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->ReleaseQueryUGCRequest(handle);
}

// Removes the dependency between the given item and the appid. This list of dependencies can be retrieved by calling GetAppDependencies.
void SteamServer::removeAppDependency(uint64_t published_file_id, uint32_t app_id){
	if(SteamUGC() != NULL){
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		AppId_t app = (uint32_t)app_id;
		SteamAPICall_t api_call = SteamUGC()->RemoveAppDependency(file_id, app);
		callResultRemoveAppDependency.Set(api_call, this, &SteamServer::remove_app_dependency_result);
	}
}

bool SteamServer::removeContentDescriptor(uint64_t update_handle, int descriptor_id){
	if(SteamUGC() == NULL){
		return false;
	}
	return SteamUGC()->RemoveContentDescriptor((UGCUpdateHandle_t)update_handle, (EUGCContentDescriptorID)descriptor_id);
}

// Removes a workshop item as a dependency from the specified item.
void SteamServer::removeDependency(uint64_t published_file_id, uint64_t child_published_file_id){
	if(SteamUGC() != NULL){
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		PublishedFileId_t childID = (uint64_t)child_published_file_id;
		SteamAPICall_t api_call = SteamUGC()->RemoveDependency(file_id, childID);
		callResultRemoveUGCDependency.Set(api_call, this, &SteamServer::remove_ugc_dependency_result);
	}
}

// Removes a workshop item from the users favorites list.
void SteamServer::removeItemFromFavorites(uint32_t app_id, uint64_t published_file_id){
	if(SteamUGC() != NULL){
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		AppId_t app = (uint32_t)app_id;
		SteamAPICall_t api_call = SteamUGC()->RemoveItemFromFavorites(app, file_id);
		callResultFavoriteItemListChanged.Set(api_call, this, &SteamServer::user_favorite_items_list_changed);
	}
}

// Removes an existing key value tag from an item.
bool SteamServer::removeItemKeyValueTags(uint64_t update_handle, const String& key){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->RemoveItemKeyValueTags(handle, key.utf8().get_data());
}

// Removes an existing preview from an item.
bool SteamServer::removeItemPreview(uint64_t update_handle, uint32 index){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->RemoveItemPreview(handle, index);
}

// Send a UGC query to Steam.
void SteamServer::sendQueryUGCRequest(uint64_t update_handle){
	if(SteamUGC() != NULL){
		UGCUpdateHandle_t handle = uint64(update_handle);
		SteamAPICall_t api_call = SteamUGC()->SendQueryUGCRequest(handle);
		callResultUGCQueryCompleted.Set(api_call, this, &SteamServer::ugc_query_completed);
	}
}

// Sets whether results will be returned from the cache for the specific period of time on a pending UGC Query.
bool SteamServer::setAllowCachedResponse(uint64_t update_handle, uint32 max_age_seconds){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetAllowCachedResponse(handle, max_age_seconds);
}

// Sets to only return items that have a specific filename on a pending UGC Query.
bool SteamServer::setCloudFileNameFilter(uint64_t update_handle, const String& match_cloud_filename){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetCloudFileNameFilter(handle, match_cloud_filename.utf8().get_data());
}

// Sets the folder that will be stored as the content for an item.
bool SteamServer::setItemContent(uint64_t update_handle, const String& content_folder){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetItemContent(handle, content_folder.utf8().get_data());
}

// Sets a new description for an item.
bool SteamServer::setItemDescription(uint64_t update_handle, const String& description){
	if(SteamUGC() == NULL){
		return false;
	}
	if ((uint32_t)description.length() > (uint32_t)k_cchPublishedDocumentDescriptionMax){
		printf("Description cannot have more than %d ASCII characters. Description not set.", k_cchPublishedDocumentDescriptionMax);
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetItemDescription(handle, description.utf8().get_data());
}

// Sets arbitrary metadata for an item. This metadata can be returned from queries without having to download and install the actual content.
bool SteamServer::setItemMetadata(uint64_t update_handle, const String& ugc_metadata){
	if(SteamUGC() == NULL){
		return false;
	}
	if (ugc_metadata.utf8().length() > 5000){
		printf("Metadata cannot be more than %d bytes. Metadata not set.", 5000);
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetItemMetadata(handle, ugc_metadata.utf8().get_data());
}

// Sets the primary preview image for the item.
bool SteamServer::setItemPreview(uint64_t update_handle, const String& preview_file){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetItemPreview(handle, preview_file.utf8().get_data());
}

// Sets arbitrary developer specified tags on an item.
bool SteamServer::setItemTags(uint64_t update_handle, Array tag_array, bool allow_admin_tags){
	bool tags_set = false;
	if (SteamUGC() != NULL) {
		UGCUpdateHandle_t handle = uint64(update_handle);
		SteamParamStringArray_t *tags = new SteamParamStringArray_t();
		tags->m_ppStrings = new const char *[tag_array.size()];
		uint32 strCount = tag_array.size();
		for (uint32 i = 0; i < strCount; i++) {
			String str = (String)tag_array[i];
			tags->m_ppStrings[i] = str.utf8().get_data();
		}
		tags->m_nNumStrings = tag_array.size();
		tags_set = SteamUGC()->SetItemTags(handle, tags, allow_admin_tags);
		delete tags;
	}
	return tags_set;
}

// Sets a new title for an item.
bool SteamServer::setItemTitle(uint64_t update_handle, const String& title){
	if(SteamUGC() == NULL){
		return false;
	}
	if (title.length() > 255){
		printf("Title cannot have more than %d ASCII characters. Title not set.", 255);
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetItemTitle(handle, title.utf8().get_data());
}

// Sets the language of the title and description that will be set in this item update.
bool SteamServer::setItemUpdateLanguage(uint64_t update_handle, const String& language){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetItemUpdateLanguage(handle, language.utf8().get_data());
}

// Sets the visibility of an item.
bool SteamServer::setItemVisibility(uint64_t update_handle, RemoteStoragePublishedFileVisibility visibility){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetItemVisibility(handle, (ERemoteStoragePublishedFileVisibility)visibility);
}

// Sets the language to return the title and description in for the items on a pending UGC Query.
bool SteamServer::setLanguage(uint64_t query_handle, const String& language){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetLanguage(handle, language.utf8().get_data());
}

// Sets whether workshop items will be returned if they have one or more matching tag, or if all tags need to match on a pending UGC Query.
bool SteamServer::setMatchAnyTag(uint64_t query_handle, bool match_any_tag){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetMatchAnyTag(handle, match_any_tag);
}

// Sets whether the order of the results will be updated based on the rank of items over a number of days on a pending UGC Query.
bool SteamServer::setRankedByTrendDays(uint64_t query_handle, uint32 days){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetRankedByTrendDays(handle, days);
}

// Sets whether to return any additional images/videos attached to the items on a pending UGC Query.
bool SteamServer::setReturnAdditionalPreviews(uint64_t query_handle, bool return_additional_previews){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetReturnAdditionalPreviews(handle, return_additional_previews);
}

// Sets whether to return the IDs of the child items of the items on a pending UGC Query.
bool SteamServer::setReturnChildren(uint64_t query_handle, bool return_children){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetReturnChildren(handle, return_children);
}

// Sets whether to return any key-value tags for the items on a pending UGC Query.
bool SteamServer::setReturnKeyValueTags(uint64_t query_handle, bool return_key_value_tags){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetReturnKeyValueTags(handle, return_key_value_tags);
}

// Sets whether to return the full description for the items on a pending UGC Query.
bool SteamServer::setReturnLongDescription(uint64_t query_handle, bool return_long_description){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetReturnLongDescription(handle, return_long_description);
}

// Sets whether to return the developer specified metadata for the items on a pending UGC Query.
bool SteamServer::setReturnMetadata(uint64_t query_handle, bool return_metadata){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetReturnMetadata(handle, return_metadata);
}

// Sets whether to only return IDs instead of all the details on a pending UGC Query.
bool SteamServer::setReturnOnlyIDs(uint64_t query_handle, bool return_only_ids){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetReturnOnlyIDs(handle, return_only_ids);
}

// Sets whether to return the the playtime stats on a pending UGC Query.
bool SteamServer::setReturnPlaytimeStats(uint64_t query_handle, uint32 days){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetReturnPlaytimeStats(handle, days);
}

// Sets whether to only return the the total number of matching items on a pending UGC Query.
bool SteamServer::setReturnTotalOnly(uint64_t query_handle, bool return_total_only){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetReturnTotalOnly(handle, return_total_only);
}

// Sets a string to that items need to match in either the title or the description on a pending UGC Query.
bool SteamServer::setSearchText(uint64_t query_handle, const String& search_text){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCQueryHandle_t handle = (uint64_t)query_handle;
	return SteamUGC()->SetSearchText(handle, search_text.utf8().get_data());
}

// Allows the user to rate a workshop item up or down.
void SteamServer::setUserItemVote(uint64_t published_file_id, bool vote_up){
	if(SteamUGC() != NULL){
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		SteamAPICall_t api_call = SteamUGC()->SetUserItemVote(file_id, vote_up);
		callResultSetUserItemVote.Set(api_call, this, &SteamServer::set_user_item_vote);
	}
}

// Starts the item update process.
uint64_t SteamServer::startItemUpdate(uint32_t app_id, uint64_t published_file_id){
	if(SteamUGC() == NULL){
		return 0;
	}
	AppId_t app = (uint32_t)app_id;
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	return SteamUGC()->StartItemUpdate(app, file_id);
}

// Start tracking playtime on a set of workshop items.
void SteamServer::startPlaytimeTracking(Array published_file_ids){
	if(SteamUGC() != NULL){
		uint32 fileCount = published_file_ids.size();
		if(fileCount > 0){
			PublishedFileId_t *file_ids = new PublishedFileId_t[fileCount];
			for(uint32 i = 0; i < fileCount; i++){
				file_ids[i] = (uint64_t)published_file_ids[i];
			}
			SteamAPICall_t api_call = SteamUGC()->StartPlaytimeTracking(file_ids, fileCount);
			callResultStartPlaytimeTracking.Set(api_call, this, &SteamServer::start_playtime_tracking);
			delete[] file_ids;
		}
	}
}

// Stop tracking playtime on a set of workshop items.
void SteamServer::stopPlaytimeTracking(Array published_file_ids){
	if(SteamUGC() != NULL){
		uint32 fileCount = published_file_ids.size();
		if(fileCount > 0){
			PublishedFileId_t *file_ids = new PublishedFileId_t[fileCount];
			Array files;
			for(uint32 i = 0; i < fileCount; i++){
				file_ids[i] = (uint64_t)published_file_ids[i];
			}
			SteamAPICall_t api_call = SteamUGC()->StopPlaytimeTracking(file_ids, fileCount);
			callResultStopPlaytimeTracking.Set(api_call, this, &SteamServer::stop_playtime_tracking);
			delete[] file_ids;
		}
	}
}

// Stop tracking playtime of all workshop items.
void SteamServer::stopPlaytimeTrackingForAllItems(){
	if(SteamUGC() != NULL){
		SteamAPICall_t api_call = SteamUGC()->StopPlaytimeTrackingForAllItems();
		callResultStopPlaytimeTracking.Set(api_call, this, &SteamServer::stop_playtime_tracking);
	}
}

// Returns any app dependencies that are associated with the given item.
void SteamServer::getAppDependencies(uint64_t published_file_id){
	if(SteamUGC() != NULL){
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		SteamAPICall_t api_call = SteamUGC()->GetAppDependencies(file_id);
		callResultGetAppDependencies.Set(api_call, this, &SteamServer::get_app_dependencies_result);
	}
}

// Uploads the changes made to an item to the Steam Workshop; to be called after setting your changes.
void SteamServer::submitItemUpdate(uint64_t update_handle, const String& change_note){
	if(SteamUGC() != NULL){
		UGCUpdateHandle_t handle = uint64(update_handle);
		SteamAPICall_t api_call;
		if (change_note.is_empty()) {
			api_call = SteamUGC()->SubmitItemUpdate(handle, NULL);
		} else {
			api_call = SteamUGC()->SubmitItemUpdate(handle, change_note.utf8().get_data());
		}
		callResultItemUpdate.Set(api_call, this, &SteamServer::item_updated);
	}
}

// Subscribe to a workshop item. It will be downloaded and installed as soon as possible.
void SteamServer::subscribeItem(uint64_t published_file_id){
	if(SteamUGC() != NULL){
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		SteamAPICall_t api_call = SteamUGC()->SubscribeItem(file_id);
		callResultSubscribeItem.Set(api_call, this, &SteamServer::subscribe_item);
	}
}

// SuspendDownloads( true ) will suspend all workshop downloads until SuspendDownloads( false ) is called or the game ends.
void SteamServer::suspendDownloads(bool suspend){
	if(SteamUGC() != NULL){
		SteamUGC()->SuspendDownloads(suspend);
	}
}

// Unsubscribe from a workshop item. This will result in the item being removed after the game quits.
void SteamServer::unsubscribeItem(uint64_t published_file_id){
	if(SteamUGC() != NULL){
		PublishedFileId_t file_id = (uint64_t)published_file_id;
		SteamAPICall_t api_call = SteamUGC()->UnsubscribeItem(file_id);
		callResultUnsubscribeItem.Set(api_call, this, &SteamServer::unsubscribe_item);
	}
}

// Updates an existing additional preview file for the item.
bool SteamServer::updateItemPreviewFile(uint64_t update_handle, uint32 index, const String& preview_file){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->UpdateItemPreviewFile(handle, index, preview_file.utf8().get_data());
}

// Updates an additional video preview from YouTube for the item.
bool SteamServer::updateItemPreviewVideo(uint64_t update_handle, uint32 index, const String& video_id){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->UpdateItemPreviewVideo(handle, index, video_id.utf8().get_data());
}

// Show the app's latest Workshop EULA to the user in an overlay window, where they can accept it or not.
bool SteamServer::showWorkshopEULA(){
	if(SteamUGC() == NULL){
		return false;
	}
	return SteamUGC()->ShowWorkshopEULA();
}

// Retrieve information related to the user's acceptance or not of the app's specific Workshop EULA.
void SteamServer::getWorkshopEULAStatus(){
	if(SteamUGC() != NULL){
		SteamAPICall_t api_call = SteamUGC()->GetWorkshopEULAStatus();
		callResultWorkshopEULAStatus.Set(api_call, this, &SteamServer::workshop_eula_status);
	}
}

// Set the time range this item was created.
bool SteamServer::setTimeCreatedDateRange(uint64_t update_handle, uint32 start, uint32 end){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetTimeCreatedDateRange(handle, start, end);
}

// Set the time range this item was updated.
bool SteamServer::setTimeUpdatedDateRange(uint64_t update_handle, uint32 start, uint32 end){
	if(SteamUGC() == NULL){
		return false;
	}
	UGCUpdateHandle_t handle = uint64(update_handle);
	return SteamUGC()->SetTimeUpdatedDateRange(handle, start, end);
}


/////////////////////////////////////////////////
///// SIGNALS / CALLBACKS
/////////////////////////////////////////////////
//
// GAME SERVER CALLBACKS ////////////////////////
//
// Called when a connection attempt has failed. This will occur periodically if the Steam client is not connected, and has failed when retrying to establish a connection.
void SteamServer::server_connect_failure(SteamServerConnectFailure_t* serverData){
	int result = serverData->m_eResult;
	bool retrying = serverData->m_bStillRetrying;
	emit_signal("server_connect_failure", result, retrying);
}

// Server has connected to the Steam back-end; serverData has no fields.
void SteamServer::server_connected(SteamServersConnected_t* serverData){
	emit_signal("server_connected");
}

// Called if the client has lost connection to the Steam servers. Real-time services will be disabled until a matching SteamServersConnected_t has been posted.
void SteamServer::server_disconnected(SteamServersDisconnected_t* serverData){
	int result = serverData->m_eResult;
	emit_signal("server_disconnected", result);
}

// Client has been approved to connect to this game server.
void SteamServer::client_approved(GSClientApprove_t* clientData){
	uint64_t steam_id = clientData->m_SteamID.ConvertToUint64();
	uint64_t owner_id = clientData->m_OwnerSteamID.ConvertToUint64();
	emit_signal("client_approved", steam_id, owner_id);
}

// Client has been denied to connection to this game server.
void SteamServer::client_denied(GSClientDeny_t* clientData){
	uint64_t steam_id = clientData->m_SteamID.ConvertToUint64();
	int reason;
	// Convert reason.
	if(clientData->m_eDenyReason == k_EDenyInvalid){
		reason = DENY_INVALID;
	}
	else if(clientData->m_eDenyReason == k_EDenyInvalidVersion){
		reason = DENY_INVALID_VERSION;
	}
	else if(clientData->m_eDenyReason == k_EDenyGeneric){
		reason = DENY_GENERIC;
	}
	else if(clientData->m_eDenyReason == k_EDenyNotLoggedOn){
		reason = DENY_NOT_LOGGED_ON;
	}
	else if(clientData->m_eDenyReason == k_EDenyNoLicense){
		reason = DENY_NO_LICENSE;
	}
	else if(clientData->m_eDenyReason == k_EDenyCheater){
		reason = DENY_CHEATER;
	}
	else if(clientData->m_eDenyReason == k_EDenyLoggedInElseWhere){
		reason = DENY_LOGGED_IN_ELSEWHERE;
	}
	else if(clientData->m_eDenyReason == k_EDenyUnknownText){
		reason = DENY_UNKNOWN_TEXT;
	}
	else if(clientData->m_eDenyReason == k_EDenyIncompatibleAnticheat){
		reason = DENY_INCOMPATIBLE_ANTI_CHEAT;
	}
	else if(clientData->m_eDenyReason == k_EDenyMemoryCorruption){
		reason = DENY_MEMORY_CORRUPTION;
	}
	else if(clientData->m_eDenyReason == k_EDenyIncompatibleSoftware){
		reason = DENY_INCOMPATIBLE_SOFTWARE;
	}
	else if(clientData->m_eDenyReason == k_EDenySteamConnectionLost){
		reason = DENY_STEAM_CONNECTION_LOST;
	}
	else if(clientData->m_eDenyReason == k_EDenySteamConnectionError){
		reason = DENY_STEAM_CONNECTION_ERROR;
	}
	else if(clientData->m_eDenyReason == k_EDenySteamResponseTimedOut){
		reason = DENY_STEAM_RESPONSE_TIMED_OUT;
	}
	else if(clientData->m_eDenyReason == k_EDenySteamValidationStalled){
		reason = DENY_STEAM_VALIDATION_STALLED;
	}
	else{
		reason = DENY_STEAM_OWNER_LEFT_GUEST_USER;
	}
	emit_signal("client_denied", steam_id, reason);
}

// Request the game server should kick the user.
void SteamServer::client_kick(GSClientKick_t* clientData){
	uint64_t steam_id = clientData->m_SteamID.ConvertToUint64();
	int reason;
	// Convert reason.
	if(clientData->m_eDenyReason == k_EDenyInvalid){
		reason = DENY_INVALID;
	}
	else if(clientData->m_eDenyReason == k_EDenyInvalidVersion){
		reason = DENY_INVALID_VERSION;
	}
	else if(clientData->m_eDenyReason == k_EDenyGeneric){
		reason = DENY_GENERIC;
	}
	else if(clientData->m_eDenyReason == k_EDenyNotLoggedOn){
		reason = DENY_NOT_LOGGED_ON;
	}
	else if(clientData->m_eDenyReason == k_EDenyNoLicense){
		reason = DENY_NO_LICENSE;
	}
	else if(clientData->m_eDenyReason == k_EDenyCheater){
		reason = DENY_CHEATER;
	}
	else if(clientData->m_eDenyReason == k_EDenyLoggedInElseWhere){
		reason = DENY_LOGGED_IN_ELSEWHERE;
	}
	else if(clientData->m_eDenyReason == k_EDenyUnknownText){
		reason = DENY_UNKNOWN_TEXT;
	}
	else if(clientData->m_eDenyReason == k_EDenyIncompatibleAnticheat){
		reason = DENY_INCOMPATIBLE_ANTI_CHEAT;
	}
	else if(clientData->m_eDenyReason == k_EDenyMemoryCorruption){
		reason = DENY_MEMORY_CORRUPTION;
	}
	else if(clientData->m_eDenyReason == k_EDenyIncompatibleSoftware){
		reason = DENY_INCOMPATIBLE_SOFTWARE;
	}
	else if(clientData->m_eDenyReason == k_EDenySteamConnectionLost){
		reason = DENY_STEAM_CONNECTION_LOST;
	}
	else if(clientData->m_eDenyReason == k_EDenySteamConnectionError){
		reason = DENY_STEAM_CONNECTION_ERROR;
	}
	else if(clientData->m_eDenyReason == k_EDenySteamResponseTimedOut){
		reason = DENY_STEAM_RESPONSE_TIMED_OUT;
	}
	else if(clientData->m_eDenyReason == k_EDenySteamValidationStalled){
		reason = DENY_STEAM_VALIDATION_STALLED;
	}
	else{
		reason = DENY_STEAM_OWNER_LEFT_GUEST_USER;
	}
	emit_signal("client_kick", steam_id, reason);
}

// Received when the game server requests to be displayed as secure (VAC protected).
// m_bSecure is true if the game server should display itself as secure to users, false otherwise.
void SteamServer::policy_response(GSPolicyResponse_t* policyData){
	uint8 secure = policyData->m_bSecure;
	emit_signal("policy_response", secure);
}

// Sent as a reply to RequestUserGroupStatus().
void SteamServer::client_group_status(GSClientGroupStatus_t* clientData){
	uint64_t steam_id = clientData->m_SteamIDUser.ConvertToUint64();
	uint64_t group_id = clientData->m_SteamIDGroup.ConvertToUint64();
	bool member = clientData->m_bMember;
	bool officer = clientData->m_bOfficer;
	emit_signal("client_group_status", steam_id, group_id, member, officer);
}

// Sent as a reply to AssociateWithClan().
void SteamServer::associate_clan(AssociateWithClanResult_t* clanData){
	int result;
	if(clanData->m_eResult == k_EResultOK){
		result = RESULT_OK;
	}
	else{
		result = RESULT_FAIL;
	}
	emit_signal("associate_clan", result);
}

// Sent as a reply to ComputeNewPlayerCompatibility().
void SteamServer::player_compat(ComputeNewPlayerCompatibilityResult_t* playerData){
	int result;
	if(playerData->m_eResult == k_EResultNoConnection){
		result = RESULT_NO_CONNECTION;
	}
	else if(playerData->m_eResult == k_EResultTimeout){
		result = RESULT_TIMEOUT;
	}
	else if(playerData->m_eResult == k_EResultFail){
		result = RESULT_FAIL;
	}
	else{
		result = RESULT_OK;
	}
	int players_dont_like_candidate = playerData->m_cPlayersThatDontLikeCandidate;
	int players_candidate_doesnt_like = playerData->m_cPlayersThatCandidateDoesntLike;
	int clan_players_dont_like_candidate = playerData->m_cClanPlayersThatDontLikeCandidate;
	uint64_t steam_id = playerData->m_SteamIDCandidate.ConvertToUint64();
	emit_signal("player_compat", result, players_dont_like_candidate, players_candidate_doesnt_like, clan_players_dont_like_candidate, steam_id);
}

// GAME SERVER STATS CALLBACKS //////////////////
//
// Result when getting the latests stats and achievements for a user from the server.
void SteamServer::stats_received(GSStatsReceived_t* callData, bool bioFailure){
	EResult result = callData->m_eResult;
	uint64_t steam_id = callData->m_steamIDUser.ConvertToUint64();
	emit_signal("stats_received", result, steam_id);
}

// Result of a request to store the user stats.
void SteamServer::stats_stored(GSStatsStored_t* callData){
	EResult result = callData->m_eResult;
	uint64_t steam_id = callData->m_steamIDUser.ConvertToUint64();
	emit_signal("stats_stored", result, steam_id);
}

// Callback indicating that a user's stats have been unloaded.
void SteamServer::stats_unloaded(GSStatsUnloaded_t* callData){
	uint64_t steam_id = callData->m_steamIDUser.ConvertToUint64();
	emit_signal("stats_unloaded", steam_id);
}

// HTTP CALLBACKS ///////////////////////////////
//
//! Result when an HTTP request completes. If you're using GetHTTPStreamingResponseBodyData then you should be using the HTTPRequestHeadersReceived_t or HTTPRequestDataReceived_t.
void SteamServer::http_request_completed(HTTPRequestCompleted_t* call_data){
	uint32 cookie_handle = call_data->m_hRequest;
	uint64_t context_value = call_data->m_ulContextValue;
	bool request_success = call_data->m_bRequestSuccessful;
	int status_code = call_data->m_eStatusCode;
	uint32 body_size = call_data->m_unBodySize;
	emit_signal("http_request_completed", cookie_handle, context_value, request_success, status_code, body_size);
}

//! Triggered when a chunk of data is received from a streaming HTTP request.
void SteamServer::http_request_data_received(HTTPRequestDataReceived_t* call_data){
	uint32 cookie_handle = call_data->m_hRequest;
	uint64_t context_value = call_data->m_ulContextValue;
	uint32 offset = call_data->m_cOffset;
	uint32 bytes_received = call_data->m_cBytesReceived;
	emit_signal("http_request_data_received", cookie_handle, context_value, offset, bytes_received);
}

//! Triggered when HTTP headers are received from a streaming HTTP request.
void SteamServer::http_request_headers_received(HTTPRequestHeadersReceived_t* call_data){
	uint32 cookie_handle = call_data->m_hRequest;
	uint64_t context_value = call_data->m_ulContextValue;
	emit_signal("http_request_headers_received", cookie_handle, context_value);
}

// INVENTORY CALLBACKS //////////////////////////
//
// This callback is triggered whenever item definitions have been updated, which could be in response to LoadItemDefinitions or any time new item definitions are available (eg, from the dynamic addition of new item types while players are still in-game).
void SteamServer::inventory_definition_update(SteamInventoryDefinitionUpdate_t *call_data){
	// Create the return array
	Array definitions;
	// Set the array size variable
	uint32 size = 0;
	// Get the item defition IDs
	if(SteamInventory()->GetItemDefinitionIDs(NULL, &size)){
		SteamItemDef_t *id_array = new SteamItemDef_t[size];
		if(SteamInventory()->GetItemDefinitionIDs(id_array, &size)){
			// Loop through the temporary array and populate the return array
			for(uint32 i = 0; i < size; i++){
				definitions.append(id_array[i]);
			}
		}
		// Delete the temporary array
		delete[] id_array;
	}
	// Return the item array as a signal
	emit_signal("inventory_defintion_update", definitions);
}

// Triggered when GetAllItems successfully returns a result which is newer / fresher than the last known result. (It will not trigger if the inventory hasn't changed, or if results from two overlapping calls are reversed in flight and the earlier result is already known to be stale/out-of-date.)
// The regular SteamInventoryResultReady_t callback will still be triggered immediately afterwards; this is an additional notification for your convenience.
void SteamServer::inventory_full_update(SteamInventoryFullUpdate_t *call_data){
	// Set the handle
	inventory_handle = call_data->m_handle;
	// Send the handle back to the user
	emit_signal("inventory_full_update", call_data->m_handle);
}

// This is fired whenever an inventory result transitions from k_EResultPending to any other completed state, see GetResultStatus for the complete list of states. There will always be exactly one callback per handle.
void SteamServer::inventory_result_ready(SteamInventoryResultReady_t *call_data){
	// Get the result
	int result = call_data->m_result;
	// Get the handle and pass it over
	inventory_handle = call_data->m_handle;
	emit_signal("inventory_result_ready", result, inventory_handle);
}

// NETWORKING CALLBACKS /////////////////////////
//
// Called when packets can't get through to the specified user. All queued packets unsent at this point will be dropped, further attempts to send will retry making the connection (but will be dropped if we fail again).
void SteamServer::p2p_session_connect_fail(P2PSessionConnectFail_t* call_data) {
	uint64_t steam_id_remote = call_data->m_steamIDRemote.ConvertToUint64();
	uint8_t session_error = call_data->m_eP2PSessionError;
	emit_signal("p2p_session_connect_fail", steam_id_remote, session_error);
}

// A user wants to communicate with us over the P2P channel via the sendP2PPacket. In response, a call to acceptP2PSessionWithUser needs to be made, if you want to open the network channel with them.
void SteamServer::p2p_session_request(P2PSessionRequest_t* call_data){
	uint64_t steam_id_remote = call_data->m_steamIDRemote.ConvertToUint64();
	emit_signal("p2p_session_request", steam_id_remote);
}

// NETWORKING MESSAGES CALLBACKS ////////////////
//
// Posted when a remote host is sending us a message, and we do not already have a session with them.
void SteamServer::network_messages_session_request(SteamNetworkingMessagesSessionRequest_t* call_data){
	SteamNetworkingIdentity remote = call_data->m_identityRemote;
	char identity[STEAM_BUFFER_SIZE];
	remote.ToString(identity, STEAM_BUFFER_SIZE);
	emit_signal("network_messages_session_request", identity);
}

// Posted when we fail to establish a connection, or we detect that communications have been disrupted it an unusual way.
void SteamServer::network_messages_session_failed(SteamNetworkingMessagesSessionFailed_t* call_data){
	SteamNetConnectionInfo_t info = call_data->m_info;
	// Parse out the reason for failure
	int reason = info.m_eEndReason;
	emit_signal("network_messages_session_failed", reason);
}

// NETWORKING SOCKETS CALLBACKS /////////////////
//
// This callback is posted whenever a connection is created, destroyed, or changes state. The m_info field will contain a complete description of the connection at the time the change occurred and the callback was posted. In particular, m_info.m_eState will have the new connection state.
void SteamServer::network_connection_status_changed(SteamNetConnectionStatusChangedCallback_t* call_data){
	// Connection handle.
	uint64_t connect_handle = call_data->m_hConn;
	// Full connection info.
	SteamNetConnectionInfo_t connection_info = call_data->m_info;
	// Move connection info into a dictionary
	Dictionary connection;
	char identity[STEAM_BUFFER_SIZE];
	connection_info.m_identityRemote.ToString(identity, STEAM_BUFFER_SIZE);
	connection["identity"] = identity;
	connection["user_data"] = (uint64_t)connection_info.m_nUserData;
	connection["listen_socket"] = connection_info.m_hListenSocket;
	char ip_address[STEAM_BUFFER_SIZE];
	connection_info.m_addrRemote.ToString(ip_address, STEAM_BUFFER_SIZE, true);
	connection["remote_address"] = ip_address;
	connection["remote_pop"] = connection_info.m_idPOPRemote;
	connection["pop_relay"] = connection_info.m_idPOPRelay;
	connection["connection_state"] = connection_info.m_eState;
	connection["end_reason"] = connection_info.m_eEndReason;
	connection["end_debug"] = connection_info.m_szEndDebug;
	connection["debug_description"] = connection_info.m_szConnectionDescription;
	// Previous state (current state is in m_info.m_eState).
	int old_state = call_data->m_eOldState;
	// Send the data back via signal
	emit_signal("network_connection_status_changed", connect_handle, connection, old_state);
}

// This callback is posted whenever the state of our readiness changes.
void SteamServer::network_authentication_status(SteamNetAuthenticationStatus_t* call_data){
	// Status.
	int available = call_data->m_eAvail;
	// Non-localized English language status. For diagnostic / debugging purposes only.
	char *debug_message = new char[256];
	sprintf(debug_message, "%s", call_data->m_debugMsg);
	// Send the data back via signal
	emit_signal("network_authentication_status", available, debug_message);
	delete[] debug_message;
}

// A struct used to describe a "fake IP" we have been assigned to use as an identifier.
// This callback is posted when ISteamNetworkingSoockets::BeginAsyncRequestFakeIP completes.
void SteamServer::fake_ip_result(SteamNetworkingFakeIPResult_t* call_data){
	int result = call_data->m_eResult;
	// Pass this new networking identity to the map
	networking_identities["fake_ip_identity"] = call_data->m_identity;
	uint32 ip = call_data->m_unIP;
	// Convert the IP address back to a string
	const int NBYTES = 4;
	uint8 octet[NBYTES];
	char fake_ip[16];
	for(int i = 0; i < NBYTES; i++){
		octet[i] = ip >> (i * 8);
	}
	sprintf(fake_ip, "%d.%d.%d.%d", octet[0], octet[1], octet[2], octet[3]);
	// Get the ports as an array
	Array port_list;
	uint16* ports = call_data->m_unPorts;
	for(uint16 i = 0; i < sizeof(ports); i++){
		port_list.append(ports[i]);
	}
	emit_signal("fake_ip_result", result, "fake_ip_identity", fake_ip, port_list);
}

// NETWORKING UTILS CALLBACKS ///////////////////
//
// A struct used to describe our readiness to use the relay network.
void SteamServer::relay_network_status(SteamRelayNetworkStatus_t* call_data){
	int available = call_data->m_eAvail;
	int ping_measurement = call_data->m_bPingMeasurementInProgress;
	int available_config = call_data->m_eAvailNetworkConfig;
	int available_relay = call_data->m_eAvailAnyRelay;
	char *debug_message = new char[256];
	sprintf(debug_message, "%s", call_data->m_debugMsg);
//	debug_message = call_data->m_debugMsg;
	emit_signal("relay_network_status", available, ping_measurement, available_config, available_relay, debug_message);
	delete[] debug_message;
}

// UGC CALLBACKS ////////////////////////////////
//
// Called when a workshop item has been downloaded.
void SteamServer::item_downloaded(DownloadItemResult_t* call_data){
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	AppId_t app_id = call_data->m_unAppID;
	emit_signal("item_downloaded", result, (uint64_t)file_id, (uint32_t)app_id);
}

// Called when a workshop item has been installed or updated.
void SteamServer::item_installed(ItemInstalled_t* call_data){
	AppId_t app_id = call_data->m_unAppID;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	emit_signal("item_installed", app_id, (uint64_t)file_id);
}

// Purpose: signal that the list of subscribed items changed.
void SteamServer::user_subscribed_items_list_changed(UserSubscribedItemsListChanged_t* call_data){
	uint32 app_id = call_data->m_nAppID;
	emit_signal("user_subscribed_items_list_changed", app_id);
}


/////////////////////////////////////////////////
///// SIGNALS / CALL RESULTS ////////////////////
/////////////////////////////////////////////////
//
// STEAMWORKS ERROR SIGNAL //////////////////////
//
//! Intended to serve as generic error messaging for failed call results
void SteamServer::steamworksError(const String& failed_signal){
	// Emit the signal to inform the user of the failure
	emit_signal("steamworks_error", failed_signal, "io failure");
}

// INVENTORY CALL RESULTS ///////////////////////
//
// Returned when you have requested the list of "eligible" promo items that can be manually granted to the given user. These are promo items of type "manual" that won't be granted automatically.
void SteamServer::inventory_eligible_promo_item(SteamInventoryEligiblePromoItemDefIDs_t *call_data, bool io_failure){
	if(io_failure){
		steamworksError("inventory_eligible_promo_item");
	}
	else{
		// Clean up call data
		CSteamID steam_id = call_data->m_steamID;
		int result = call_data->m_result;
		int eligible = call_data->m_numEligiblePromoItemDefs;
		bool cached = call_data->m_bCachedData;
		// Create the return array
		Array definitions;
		// Create the temporary ID array
		SteamItemDef_t *id_array = new SteamItemDef_t[eligible];
		// Convert eligible size
		uint32 array_size = (int)eligible;
		// Get the list
		if(SteamInventory()->GetEligiblePromoItemDefinitionIDs(steam_id, id_array, &array_size)){
			// Loop through the temporary array and populate the return array
			for(int i = 0; i < eligible; i++){
				definitions.append(id_array[i]);
			}
		}
		// Delete the temporary array
		delete[] id_array;
		// Return the item array as a signal
		emit_signal("inventory_eligible_promo_Item", result, cached, definitions);
	}
}

// Returned after StartPurchase is called.
void SteamServer::inventory_start_purchase_result(SteamInventoryStartPurchaseResult_t *call_data, bool io_failure){
	if(io_failure){
		steamworksError("inventory_start_purchase_result");
	}
	else{
		if(call_data->m_result == k_EResultOK){
			uint64_t order_id = call_data->m_ulOrderID;
			uint64_t transaction_id = call_data->m_ulTransID;
			emit_signal("inventory_start_purchase_result", "success", order_id, transaction_id);
		}
		else{
			emit_signal("inventory_start_purchase_result", "failure", 0, 0);
		}
	}
}

// Returned after RequestPrices is called.
void SteamServer::inventory_request_prices_result(SteamInventoryRequestPricesResult_t *call_data, bool io_failure){
	if(io_failure){
		steamworksError("inventory_request_prices_result");
	}
	else{
		int result = call_data->m_result;
		String currency = call_data->m_rgchCurrency;
		emit_signal("inventory_request_prices_result", result, currency);
	}
}

// REMOTE STORAGE CALL RESULTS //////////////////
//
// Response when downloading UGC
void SteamServer::download_ugc_result(RemoteStorageDownloadUGCResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("download_ugc_result");
	}
	else{
		int result = call_data->m_eResult;
		uint64_t handle = call_data->m_hFile;
		uint32_t app_id = call_data->m_nAppID;
		int32 size = call_data->m_nSizeInBytes;
		char filename[k_cchFilenameMax];
		strcpy(filename, call_data->m_pchFileName);
		uint64_t owner_id = call_data->m_ulSteamIDOwner;
		// Pass some variable to download dictionary to bypass argument limit
		Dictionary download_data;
		download_data["handle"] = handle;
		download_data["app_id"] = app_id;
		download_data["size"] = size;
		download_data["filename"] = filename;
		download_data["owner_id"] = owner_id;
		emit_signal("download_ugc_result", result, download_data);
	}
}

// Called when the user has unsubscribed from a piece of UGC. Result from ISteamUGC::UnsubscribeItem.
void SteamServer::unsubscribe_item(RemoteStorageUnsubscribePublishedFileResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("unsubscribe_item");
	}
	else{
		int result = call_data->m_eResult;
		int file_id = call_data->m_nPublishedFileId;
		emit_signal("unsubscribe_item", result, file_id);
	}
}

// Called when the user has subscribed to a piece of UGC. Result from ISteamUGC::SubscribeItem.
void SteamServer::subscribe_item(RemoteStorageSubscribePublishedFileResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("subscribe_item");
	}
	else{
		int result = call_data->m_eResult;
		int file_id = call_data->m_nPublishedFileId;
		emit_signal("subscribe_item", result, file_id);
	}
}

// UGC CALL RESULTS /////////////////////////////
//
// The result of a call to AddAppDependency.
void SteamServer::add_app_dependency_result(AddAppDependencyResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("add_app_dependency_result");
	}
	else{
		EResult result = call_data->m_eResult;
		PublishedFileId_t file_id = call_data->m_nPublishedFileId;
		AppId_t app_id = call_data->m_nAppID;
		emit_signal("add_app_dependency_result", result, (uint64_t)file_id, (uint32_t)app_id);
	}
}

// The result of a call to AddDependency.
void SteamServer::add_ugc_dependency_result(AddUGCDependencyResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("add_ugc_dependency_result");
	}
	else{
		EResult result = call_data->m_eResult;
		PublishedFileId_t file_id = call_data->m_nPublishedFileId;
		PublishedFileId_t child_id = call_data->m_nChildPublishedFileId;
		emit_signal("add_ugc_dependency_result", result, (uint64_t)file_id, (uint64_t)child_id);
	}
}

// Result of a workshop item being created.
void SteamServer::item_created(CreateItemResult_t *call_data, bool io_failure){
	if(io_failure){
		steamworksError("item_created");
	}
	else{
		EResult result = call_data->m_eResult;
		PublishedFileId_t file_id = call_data->m_nPublishedFileId;
		bool accept_tos = call_data->m_bUserNeedsToAcceptWorkshopLegalAgreement;
		emit_signal("item_created", result, (uint64_t)file_id, accept_tos);
	}
}

// Called when getting the app dependencies for an item.
void SteamServer::get_app_dependencies_result(GetAppDependenciesResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("get_app_dependencies_result");
	}
	else{
		EResult result = call_data->m_eResult;
		PublishedFileId_t file_id = call_data->m_nPublishedFileId;
//		AppId_t app_id = call_data->m_rgAppIDs;
		uint32 app_dependencies = call_data->m_nNumAppDependencies;
		uint32 total_app_dependencies = call_data->m_nTotalNumAppDependencies;
//		emit_signal("get_app_dependencies_result", result, (uint64_t)file_id, app_id, appDependencies, totalAppDependencies);
		emit_signal("get_app_dependencies_result", result, (uint64_t)file_id, app_dependencies, total_app_dependencies);
	}
}

// Called when an attempt at deleting an item completes.
void SteamServer::item_deleted(DeleteItemResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("item_deleted");
	}
	else{
		EResult result = call_data->m_eResult;
		PublishedFileId_t file_id = call_data->m_nPublishedFileId;
		emit_signal("item_deleted", result, (uint64_t)file_id);
	}
}

// Called when getting the users vote status on an item.
void SteamServer::get_item_vote_result(GetUserItemVoteResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("get_item_vote_result");
	}
	else{
		EResult result = call_data->m_eResult;
		PublishedFileId_t file_id = call_data->m_nPublishedFileId;
		bool vote_up = call_data->m_bVotedUp;
		bool vote_down = call_data->m_bVotedDown;
		bool vote_skipped = call_data->m_bVoteSkipped;
		emit_signal("get_item_vote_result", result, (uint64_t)file_id, vote_up, vote_down, vote_skipped);
	}
}

// Purpose: The result of a call to RemoveAppDependency.
void SteamServer::remove_app_dependency_result(RemoveAppDependencyResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("remove_app_dependency_result");
	}
	else{
		EResult result = call_data->m_eResult;
		PublishedFileId_t file_id = call_data->m_nPublishedFileId;
		AppId_t app_id = call_data->m_nAppID;
		emit_signal("remove_app_dependency_result", result, (uint64_t)file_id, (uint32_t)app_id);
	}
}

// Purpose: The result of a call to RemoveDependency.
void SteamServer::remove_ugc_dependency_result(RemoveUGCDependencyResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("remove_ugc_dependency_result");
	}
	else{
		EResult result = call_data->m_eResult;
		PublishedFileId_t file_id = call_data->m_nPublishedFileId;
		PublishedFileId_t child_id = call_data->m_nChildPublishedFileId;
		emit_signal("remove_ugc_dependency_result", result, (uint64_t)file_id, (uint64_t)child_id);
	}
}

// Called when the user has voted on an item.
void SteamServer::set_user_item_vote(SetUserItemVoteResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("set_user_item_vote");
	}
	else{
		EResult result = call_data->m_eResult;
		PublishedFileId_t file_id = call_data->m_nPublishedFileId;
		bool vote_up = call_data->m_bVoteUp;
		emit_signal("set_user_item_vote", result, (uint64_t)file_id, vote_up);
	}
}

// Called when workshop item playtime tracking has started.
void SteamServer::start_playtime_tracking(StartPlaytimeTrackingResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("start_playtime_tracking");
	}
	else{
		EResult result = call_data->m_eResult;
		emit_signal("start_playtime_tracking", result);
	}
}

// Called when a UGC query request completes.
void SteamServer::ugc_query_completed(SteamUGCQueryCompleted_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("ugc_query_completed");
	}
	else{
		UGCQueryHandle_t handle = call_data->m_handle;
		EResult result = call_data->m_eResult;
		uint32 results_returned = call_data->m_unNumResultsReturned;
		uint32 total_matching = call_data->m_unTotalMatchingResults;
		bool cached = call_data->m_bCachedData;
		emit_signal("ugc_query_completed", (uint64_t)handle, result, results_returned, total_matching, cached);
	}
}

// Called when workshop item playtime tracking has stopped.
void SteamServer::stop_playtime_tracking(StopPlaytimeTrackingResult_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("stop_playtime_tracking");
	}
	else{
		EResult result = call_data->m_eResult;
		emit_signal("stop_playtime_tracking", result);
	}
}

// Result of a workshop item being updated.
void SteamServer::item_updated(SubmitItemUpdateResult_t *call_data, bool io_failure){
	if(io_failure){
		steamworksError("item_updated");
	}
	else{
		EResult result = call_data->m_eResult;
		bool accept_tos = call_data->m_bUserNeedsToAcceptWorkshopLegalAgreement;
		emit_signal("item_updated", result, accept_tos);
	}
}

// Called when the user has added or removed an item to/from their favorites.
void SteamServer::user_favorite_items_list_changed(UserFavoriteItemsListChanged_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("user_favorite_items_list_changed");
	}
	else{
		EResult result = call_data->m_eResult;
		PublishedFileId_t file_id = call_data->m_nPublishedFileId;
		bool was_add_request = call_data->m_bWasAddRequest;
		emit_signal("user_favorite_items_list_changed", result, (uint64_t)file_id, was_add_request);
	}
}

// Purpose: Status of the user's acceptable/rejection of the app's specific Workshop EULA.
void SteamServer::workshop_eula_status(WorkshopEULAStatus_t* call_data, bool io_failure){
	if(io_failure){
		steamworksError("workshop_eula_status");
	}
	else{
		int result = call_data->m_eResult;
		uint32 app_id = call_data->m_nAppID;
		// Slim down signal arguments since Godot seems to limit them to six max
		Dictionary eula_data;
		eula_data["version"] = call_data->m_unVersion;			// int
		eula_data["action"] = call_data->m_rtAction;			// int
		eula_data["accepted"] = call_data->m_bAccepted;			// bool
		eula_data["needs_action"] = call_data->m_bNeedsAction;	// bool
		emit_signal("workshop_eula_status", result, app_id, eula_data);
	}
}


/////////////////////////////////////////////////
///// BIND METHODS //////////////////////////////
/////////////////////////////////////////////////
//
void SteamServer::_bind_methods(){
	/////////////////////////////////////////////
	// FUNCTION BINDS ///////////////////////////
	/////////////////////////////////////////////
	//
	// MAIN BIND METHODS ////////////////////////
	ClassDB::bind_method(D_METHOD("isServerSecure"), &SteamServer::isServerSecure);
	ClassDB::bind_method(D_METHOD("getServerSteamID"), &SteamServer::getServerSteamID);
	ClassDB::bind_method(D_METHOD("run_callbacks"), &SteamServer::run_callbacks);
	ClassDB::bind_method(D_METHOD("serverInit", "ip", "game_port", "query_port", "server_mode", "version_number"), &SteamServer::serverInit);
	ClassDB::bind_method(D_METHOD("serverInitEx", "ip", "game_port", "query_port", "server_mode", "version_number"), &SteamServer::serverInitEx);
	ClassDB::bind_method(D_METHOD("serverReleaseCurrentThreadMemory"), &SteamServer::serverReleaseCurrentThreadMemory);
	ClassDB::bind_method(D_METHOD("serverShutdown"), &SteamServer::serverShutdown);

	// GAME SERVER BIND METHODS /////////////////
	ClassDB::bind_method(D_METHOD("associateWithClan", "clan_id"), &SteamServer::associateWithClan);
	ClassDB::bind_method(D_METHOD("beginAuthSession", "ticket", "ticket_size", "steam_id"), &SteamServer::beginAuthSession);
	ClassDB::bind_method(D_METHOD("cancelAuthTicket", "auth_ticket"), &SteamServer::cancelAuthTicket);
	ClassDB::bind_method(D_METHOD("clearAllKeyValues"), &SteamServer::clearAllKeyValues);
	ClassDB::bind_method(D_METHOD("computeNewPlayerCompatibility", "steam_id"), &SteamServer::computeNewPlayerCompatibility);
	ClassDB::bind_method(D_METHOD("endAuthSession", "steam_id"), &SteamServer::endAuthSession);
	ClassDB::bind_method(D_METHOD("getAuthSessionTicket"), &SteamServer::getAuthSessionTicket);
	ClassDB::bind_method(D_METHOD("getNextOutgoingPacket"), &SteamServer::getNextOutgoingPacket);
	ClassDB::bind_method(D_METHOD("getPublicIP"), &SteamServer::getPublicIP);
	ClassDB::bind_method(D_METHOD("getSteamID"), &SteamServer::getSteamID);
	ClassDB::bind_method(D_METHOD("handleIncomingPacket", "packet", "ip", "port"), &SteamServer::handleIncomingPacket);
	ClassDB::bind_method(D_METHOD("loggedOn"), &SteamServer::loggedOn);
	ClassDB::bind_method(D_METHOD("logOff"), &SteamServer::logOff);
	ClassDB::bind_method(D_METHOD("logOn", "token"), &SteamServer::logOn);
	ClassDB::bind_method(D_METHOD("logOnAnonymous"), &SteamServer::logOnAnonymous);
	ClassDB::bind_method(D_METHOD("requestUserGroupStatus", "steam_id", "group_id"), &SteamServer::requestUserGroupStatus);
	ClassDB::bind_method(D_METHOD("secure"), &SteamServer::secure);
	ClassDB::bind_method(D_METHOD("setAdvertiseServerActive", "active"), &SteamServer::setAdvertiseServerActive);
	ClassDB::bind_method(D_METHOD("setBotPlayerCount", "bots"), &SteamServer::setBotPlayerCount);
	ClassDB::bind_method(D_METHOD("setDedicatedServer", "dedicated"), &SteamServer::setDedicatedServer);
	ClassDB::bind_method(D_METHOD("setGameData", "data"), &SteamServer::setGameData);
	ClassDB::bind_method(D_METHOD("setGameDescription", "description"), &SteamServer::setGameDescription);
	ClassDB::bind_method(D_METHOD("setGameTags", "tags"), &SteamServer::setGameTags);
	ClassDB::bind_method(D_METHOD("setKeyValue", "key", "value"), &SteamServer::setKeyValue);
	ClassDB::bind_method(D_METHOD("setMapName", "map"), &SteamServer::setMapName);
	ClassDB::bind_method(D_METHOD("setMaxPlayerCount", "players_max"), &SteamServer::setMaxPlayerCount);
	ClassDB::bind_method(D_METHOD("setModDir", "mod_directory"), &SteamServer::setModDir);
	ClassDB::bind_method(D_METHOD("setPasswordProtected", "password_protected"), &SteamServer::setPasswordProtected);
	ClassDB::bind_method(D_METHOD("setProduct", "product"), &SteamServer::setProduct);
	ClassDB::bind_method(D_METHOD("setRegion", "region"), &SteamServer::setRegion);
	ClassDB::bind_method(D_METHOD("setServerName", "name"), &SteamServer::setServerName);
	ClassDB::bind_method(D_METHOD("setSpectatorPort", "port"), &SteamServer::setSpectatorPort);
	ClassDB::bind_method(D_METHOD("setSpectatorServerName", "name"), &SteamServer::setSpectatorServerName);
	ClassDB::bind_method(D_METHOD("userHasLicenceForApp", "steam_id", "app_id"), &SteamServer::userHasLicenceForApp);
	ClassDB::bind_method(D_METHOD("wasRestartRequested"), &SteamServer::wasRestartRequested);	
	
	// GAME SERVER STATS BIND METHODS ///////////
	ClassDB::bind_method(D_METHOD("clearUserAchievement", "steam_id", "name"), &SteamServer::clearUserAchievement);
	ClassDB::bind_method(D_METHOD("getUserAchievement", "steam_id", "name"), &SteamServer::getUserAchievement);
	ClassDB::bind_method(D_METHOD("getUserStatInt", "steam_id", "name"), &SteamServer::getUserStatInt);
	ClassDB::bind_method(D_METHOD("getUserStatFloat", "steam_id", "name"), &SteamServer::getUserStatFloat);
	ClassDB::bind_method(D_METHOD("requestUserStats", "steam_id"), &SteamServer::requestUserStats);
	ClassDB::bind_method(D_METHOD("setUserAchievement", "steam_id", "name"), &SteamServer::setUserAchievement);
	ClassDB::bind_method(D_METHOD("setUserStatInt", "steam_id", "name", "stat"), &SteamServer::setUserStatInt);
	ClassDB::bind_method(D_METHOD("setUserStatFloat", "steam_id", "name", "stat"), &SteamServer::setUserStatFloat);
	ClassDB::bind_method(D_METHOD("storeUserStats", "steam_id"), &SteamServer::storeUserStats);
	ClassDB::bind_method(D_METHOD("updateUserAvgRateStat", "steam_id", "name", "this_session", "session_length"), &SteamServer::updateUserAvgRateStat);

	// HTTP BIND METHODS ////////////////////////
	ClassDB::bind_method(D_METHOD("createCookieContainer", "allow_response_to_modify"), &SteamServer::createCookieContainer);
	ClassDB::bind_method(D_METHOD("createHTTPRequest", "request_method", "absolute_url"), &SteamServer::createHTTPRequest);
	ClassDB::bind_method(D_METHOD("deferHTTPRequest", "request_handle"), &SteamServer::deferHTTPRequest);
	ClassDB::bind_method(D_METHOD("getHTTPDownloadProgressPct", "request_handle"), &SteamServer::getHTTPDownloadProgressPct);
	ClassDB::bind_method(D_METHOD("getHTTPRequestWasTimedOut", "request_handle"), &SteamServer::getHTTPRequestWasTimedOut);
	ClassDB::bind_method(D_METHOD("getHTTPResponseBodyData", "request_handle", "buffer_size"), &SteamServer::getHTTPResponseBodyData);
	ClassDB::bind_method(D_METHOD("getHTTPResponseBodySize", "request_handle"), &SteamServer::getHTTPResponseBodySize);
	ClassDB::bind_method(D_METHOD("getHTTPResponseHeaderSize", "request_handle", "header_name"), &SteamServer::getHTTPResponseHeaderSize);
	ClassDB::bind_method(D_METHOD("getHTTPResponseHeaderValue","request_handle", "header_name", "buffer_size"), &SteamServer::getHTTPResponseHeaderValue);
	ClassDB::bind_method(D_METHOD("getHTTPStreamingResponseBodyData", "request_handle", "offset", "buffer_size"), &SteamServer::getHTTPStreamingResponseBodyData);
	ClassDB::bind_method(D_METHOD("prioritizeHTTPRequest", "request_handle"), &SteamServer::prioritizeHTTPRequest);
	ClassDB::bind_method(D_METHOD("releaseCookieContainer", "cookie_handle"), &SteamServer::releaseCookieContainer);
	ClassDB::bind_method(D_METHOD("releaseHTTPRequest", "request_handle"), &SteamServer::releaseHTTPRequest);
	ClassDB::bind_method(D_METHOD("sendHTTPRequest", "request_handle"), &SteamServer::sendHTTPRequest);
	ClassDB::bind_method(D_METHOD("sendHTTPRequestAndStreamResponse", "request_handle"), &SteamServer::sendHTTPRequestAndStreamResponse);
	ClassDB::bind_method(D_METHOD("setHTTPCookie", "cookie_handle", "host", "url", "cookie"), &SteamServer::setHTTPCookie);
	ClassDB::bind_method(D_METHOD("setHTTPRequestAbsoluteTimeoutMS", "request_handle", "milliseconds"), &SteamServer::setHTTPRequestAbsoluteTimeoutMS);
	ClassDB::bind_method(D_METHOD("setHTTPRequestContextValue", "request_handle", "context_value"), &SteamServer::setHTTPRequestContextValue);
	ClassDB::bind_method(D_METHOD("setHTTPRequestCookieContainer", "request_handle", "cookie_handle"), &SteamServer::setHTTPRequestCookieContainer);
	ClassDB::bind_method(D_METHOD("setHTTPRequestGetOrPostParameter", "request_handle", "name", "value"), &SteamServer::setHTTPRequestGetOrPostParameter);
	ClassDB::bind_method(D_METHOD("setHTTPRequestHeaderValue", "request_handle", "header_name", "header_value"), &SteamServer::setHTTPRequestHeaderValue);
	ClassDB::bind_method(D_METHOD("setHTTPRequestNetworkActivityTimeout", "request_handle", "timeout_seconds"), &SteamServer::setHTTPRequestNetworkActivityTimeout);
	ClassDB::bind_method(D_METHOD("setHTTPRequestRawPostBody", "request_handle", "content_type", "body_length"), &SteamServer::setHTTPRequestRawPostBody);
	ClassDB::bind_method(D_METHOD("setHTTPRequestRequiresVerifiedCertificate", "request_handle", "require_verified_certificate"), &SteamServer::setHTTPRequestRequiresVerifiedCertificate);
	ClassDB::bind_method(D_METHOD("setHTTPRequestUserAgentInfo", "request_handle", "user_agent_info"), &SteamServer::setHTTPRequestUserAgentInfo);

	// INVENTORY BIND METHODS ///////////////////
	ClassDB::bind_method(D_METHOD("addPromoItem", "item"), &SteamServer::addPromoItem);
	ClassDB::bind_method(D_METHOD("addPromoItems", "items"), &SteamServer::addPromoItems);
	ClassDB::bind_method(D_METHOD("checkResultSteamID", "steam_id_expected", "this_inventory_handle"), &SteamServer::checkResultSteamID, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("consumeItem", "item_consume", "quantity"), &SteamServer::consumeItem);
	ClassDB::bind_method(D_METHOD("deserializeResult", "buffer"), &SteamServer::deserializeResult);
	ClassDB::bind_method(D_METHOD("destroyResult", "this_inventory_handle"), &SteamServer::destroyResult, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("exchangeItems", "output_items", "output_quantity", "input_items", "input_quantity"), &SteamServer::exchangeItems);
	ClassDB::bind_method(D_METHOD("generateItems", "items", "quantity"), &SteamServer::generateItems);
	ClassDB::bind_method(D_METHOD("getAllItems"), &SteamServer::getAllItems);
	ClassDB::bind_method(D_METHOD("getItemDefinitionProperty", "definition", "name"), &SteamServer::getItemDefinitionProperty);
	ClassDB::bind_method(D_METHOD("getItemsByID", "id_array", "count"), &SteamServer::getItemsByID);
	ClassDB::bind_method(D_METHOD("getItemPrice", "definition"), &SteamServer::getItemPrice);
	ClassDB::bind_method(D_METHOD("getItemsWithPrices", "length"), &SteamServer::getItemsWithPrices);
	ClassDB::bind_method(D_METHOD("getNumItemsWithPrices"), &SteamServer::getNumItemsWithPrices);
	ClassDB::bind_method(D_METHOD("getResultItemProperty", "index", "name", "this_inventory_handle"), &SteamServer::getResultItemProperty, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("getResultItems", "this_inventory_handle"), &SteamServer::getResultItems, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("getResultStatus", "this_inventory_handle"), &SteamServer::getResultStatus, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("getResultTimestamp", "this_inventory_handle"), &SteamServer::getResultTimestamp, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("grantPromoItems"), &SteamServer::grantPromoItems);
	ClassDB::bind_method(D_METHOD("loadItemDefinitions"), &SteamServer::loadItemDefinitions);
	ClassDB::bind_method(D_METHOD("requestEligiblePromoItemDefinitionsIDs", "steam_id"), &SteamServer::requestEligiblePromoItemDefinitionsIDs);
	ClassDB::bind_method(D_METHOD("requestPrices"), &SteamServer::requestPrices);
	ClassDB::bind_method(D_METHOD("serializeResult", "this_inventory_handle"), &SteamServer::serializeResult, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("startPurchase", "items", "quantity"), &SteamServer::startPurchase);
	ClassDB::bind_method(D_METHOD("transferItemQuantity", "item_id", "quantity", "item_destination", "split"), &SteamServer::transferItemQuantity);
	ClassDB::bind_method(D_METHOD("triggerItemDrop", "definition"), &SteamServer::triggerItemDrop);
	ClassDB::bind_method(D_METHOD("startUpdateProperties"), &SteamServer::startUpdateProperties);
	ClassDB::bind_method(D_METHOD("submitUpdateProperties", "this_inventory_update_handle"), &SteamServer::submitUpdateProperties, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("removeProperty", "item_id", "name", "this_inventory_update_handle"), &SteamServer::removeProperty, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("setPropertyString", "item_id", "name", "value", "this_inventory_update_handle"), &SteamServer::setPropertyString, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("setPropertyBool", "item_id", "name", "value", "this_inventory_update_handle"), &SteamServer::setPropertyBool, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("setPropertyInt", "item_id", "name", "value", "this_inventory_update_handle"), &SteamServer::setPropertyInt, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("setPropertyFloat", "item_id", "name", "value", "this_inventory_update_handle"), &SteamServer::setPropertyFloat, DEFVAL(0));

	// NETWORKING BIND METHODS //////////////////
	ClassDB::bind_method(D_METHOD("acceptP2PSessionWithUser", "steam_id_remote"), &SteamServer::acceptP2PSessionWithUser);
	ClassDB::bind_method(D_METHOD("allowP2PPacketRelay", "allow"), &SteamServer::allowP2PPacketRelay);
	ClassDB::bind_method(D_METHOD("closeP2PChannelWithUser", "steam_id_remote", "channel"), &SteamServer::closeP2PChannelWithUser);
	ClassDB::bind_method(D_METHOD("closeP2PSessionWithUser", "steam_id_remote"), &SteamServer::closeP2PSessionWithUser);
	ClassDB::bind_method(D_METHOD("getP2PSessionState", "steam_id_remote"), &SteamServer::getP2PSessionState);
	ClassDB::bind_method(D_METHOD("getAvailableP2PPacketSize", "channel"), &SteamServer::getAvailableP2PPacketSize, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("readP2PPacket", "packet", "channel"), &SteamServer::readP2PPacket, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("sendP2PPacket", "steam_id_remote", "data", "send_type", "channel"), &SteamServer::sendP2PPacket, DEFVAL(0));

	// NETWORKING MESSAGES BIND METHODS /////////
	ClassDB::bind_method(D_METHOD("acceptSessionWithUser", "identity_reference"), &SteamServer::acceptSessionWithUser);
	ClassDB::bind_method(D_METHOD("closeChannelWithUser", "identity_reference", "channel"), &SteamServer::closeChannelWithUser);
	ClassDB::bind_method(D_METHOD("closeSessionWithUser", "identity_reference"), &SteamServer::closeSessionWithUser);
	ClassDB::bind_method(D_METHOD("getSessionConnectionInfo", "identity_reference", "get_connection", "get_status"), &SteamServer::getSessionConnectionInfo);
	ClassDB::bind_method(D_METHOD("receiveMessagesOnChannel", "channel", "max_messages"), &SteamServer::receiveMessagesOnChannel);
	ClassDB::bind_method(D_METHOD("sendMessageToUser", "identity_reference", "data", "flags", "channel"), &SteamServer::sendMessageToUser);
	
	// NETWORKING SOCKETS BIND METHODS //////////
	ClassDB::bind_method(D_METHOD("acceptConnection", "connection"), &SteamServer::acceptConnection);
	ClassDB::bind_method(D_METHOD("beginAsyncRequestFakeIP", "num_ports"), &SteamServer::beginAsyncRequestFakeIP);
	ClassDB::bind_method(D_METHOD("closeConnection", "peer", "reason", "debug_message", "linger"), &SteamServer::closeConnection);
	ClassDB::bind_method(D_METHOD("closeListenSocket", "socket"), &SteamServer::closeListenSocket);
	ClassDB::bind_method(D_METHOD("configureConnectionLanes", "connection", "lanes", "priorities", "weights"), &SteamServer::configureConnectionLanes);
	ClassDB::bind_method(D_METHOD("connectP2P", "identity_reference", "virtual_port", "options"), &SteamServer::connectP2P);
	ClassDB::bind_method(D_METHOD("connectByIPAddress", "ip_address_with_port", "options"), &SteamServer::connectByIPAddress);
	ClassDB::bind_method(D_METHOD("connectToHostedDedicatedServer", "identity_reference", "virtual_port", "options"), &SteamServer::connectToHostedDedicatedServer);
	ClassDB::bind_method(D_METHOD("createFakeUDPPort", "fake_server_port"), &SteamServer::createFakeUDPPort);
	ClassDB::bind_method(D_METHOD("createHostedDedicatedServerListenSocket", "virtual_port", "options"), &SteamServer::createHostedDedicatedServerListenSocket);
	ClassDB::bind_method(D_METHOD("createListenSocketIP", "ip_reference", "options"), &SteamServer::createListenSocketIP);
	ClassDB::bind_method(D_METHOD("createListenSocketP2P", "virtual_port", "options"), &SteamServer::createListenSocketP2P);
	ClassDB::bind_method(D_METHOD("createListenSocketP2PFakeIP", "fake_port", "options"), &SteamServer::createListenSocketP2PFakeIP);
	ClassDB::bind_method(D_METHOD("createPollGroup"), &SteamServer::createPollGroup);
	ClassDB::bind_method(D_METHOD("createSocketPair", "loopback", "identity_reference1", "identity_reference2"), &SteamServer::createSocketPair);
	ClassDB::bind_method(D_METHOD("destroyPollGroup", "poll_group"), &SteamServer::destroyPollGroup);
//	ClassDB::bind_method(D_METHOD("findRelayAuthTicketForServer", "port"), &SteamServer::findRelayAuthTicketForServer);	<------ Uses datagram relay structs which were removed from base SDK
	ClassDB::bind_method(D_METHOD("flushMessagesOnConnection", "connection_handle"), &SteamServer::flushMessagesOnConnection);
	ClassDB::bind_method(D_METHOD("getAuthenticationStatus"), &SteamServer::getAuthenticationStatus);		
	ClassDB::bind_method(D_METHOD("getCertificateRequest"), &SteamServer::getCertificateRequest);
	ClassDB::bind_method(D_METHOD("getConnectionInfo", "connection_handle"), &SteamServer::getConnectionInfo);
	ClassDB::bind_method(D_METHOD("getConnectionName", "peer"), &SteamServer::getConnectionName);
	ClassDB::bind_method(D_METHOD("getConnectionRealTimeStatus", "connection_handle", "lanes", "get_status"), &SteamServer::getConnectionRealTimeStatus, DEFVAL(true));
	ClassDB::bind_method(D_METHOD("getConnectionUserData", "peer"), &SteamServer::getConnectionUserData);
	ClassDB::bind_method(D_METHOD("getDetailedConnectionStatus", "connection_handle"), &SteamServer::getDetailedConnectionStatus);
	ClassDB::bind_method(D_METHOD("getFakeIP", "first_port"), &SteamServer::getFakeIP, DEFVAL(0));
//	ClassDB::bind_method(D_METHOD("getGameCoordinatorServerLogin", "app_data"), &SteamServer::getGameCoordinatorServerLogin);	<------ Uses datagram relay structs which were removed from base SDK
//	ClassDB::bind_method(D_METHOD("getHostedDedicatedServerAddress"), &SteamServer::getHostedDedicatedServerAddress);	<------ Uses datagram relay structs which were removed from base SDK
	ClassDB::bind_method(D_METHOD("getHostedDedicatedServerPOPId"), &SteamServer::getHostedDedicatedServerPOPId);
	ClassDB::bind_method(D_METHOD("getHostedDedicatedServerPort"), &SteamServer::getHostedDedicatedServerPort);
	ClassDB::bind_method(D_METHOD("getListenSocketAddress", "socket"), &SteamServer::getListenSocketAddress);
	ClassDB::bind_method(D_METHOD("getIdentity"), &SteamServer::getIdentity);
	ClassDB::bind_method(D_METHOD("getRemoteFakeIPForConnection", "connection"), &SteamServer::getRemoteFakeIPForConnection);
	ClassDB::bind_method(D_METHOD("initAuthentication"), &SteamServer::initAuthentication);
	ClassDB::bind_method(D_METHOD("receiveMessagesOnConnection", "connection", "max_messages"), &SteamServer::receiveMessagesOnConnection);	
	ClassDB::bind_method(D_METHOD("receiveMessagesOnPollGroup", "poll_group", "max_messages"), &SteamServer::receiveMessagesOnPollGroup);
//	ClassDB::bind_method(D_METHOD("receivedRelayAuthTicket"), &SteamServer::receivedRelayAuthTicket);	<------ Uses datagram relay structs which were removed from base SDK
	ClassDB::bind_method(D_METHOD("resetIdentity", "this_identity"), &SteamServer::resetIdentity);
	ClassDB::bind_method(D_METHOD("runNetworkingCallbacks"), &SteamServer::runNetworkingCallbacks);
	ClassDB::bind_method(D_METHOD("sendMessages", "messages", "data", "connection_handle", "flags"), &SteamServer::sendMessages);
	ClassDB::bind_method(D_METHOD("sendMessageToConnection", "connection_handle", "data", "flags"), &SteamServer::sendMessageToConnection);
	ClassDB::bind_method(D_METHOD("setCertificate", "certificate"), &SteamServer::setCertificate);	
	ClassDB::bind_method(D_METHOD("setConnectionPollGroup", "connection_handle", "poll_group"), &SteamServer::setConnectionPollGroup);
	ClassDB::bind_method(D_METHOD("setConnectionName", "peer", "name"), &SteamServer::setConnectionName);
	
	// NETWORKING TYPES BIND METHODS ////////////
	ClassDB::bind_method(D_METHOD("addIdentity", "reference_name"), &SteamServer::addIdentity);
	ClassDB::bind_method(D_METHOD("addIPAddress", "reference_name"), &SteamServer::addIPAddress);
	ClassDB::bind_method(D_METHOD("clearIdentity", "reference_name"), &SteamServer::clearIdentity);
	ClassDB::bind_method(D_METHOD("clearIPAddress", "reference_name"), &SteamServer::clearIPAddress);
	ClassDB::bind_method(D_METHOD("getGenericBytes", "reference_name"), &SteamServer::getGenericBytes);
	ClassDB::bind_method(D_METHOD("getGenericString", "reference_name"), &SteamServer::getGenericString);
	ClassDB::bind_method(D_METHOD("getIdentities"), &SteamServer::getIdentities);
	ClassDB::bind_method(D_METHOD("getIdentityIPAddr", "reference_name"), &SteamServer::getIdentityIPAddr);
	ClassDB::bind_method(D_METHOD("getIdentitySteamID", "reference_name"), &SteamServer::getIdentitySteamID);
	ClassDB::bind_method(D_METHOD("getIdentitySteamID64", "reference_name"), &SteamServer::getIdentitySteamID64);
	ClassDB::bind_method(D_METHOD("getIPAddresses"), &SteamServer::getIPAddresses);
	ClassDB::bind_method(D_METHOD("getIPv4", "reference_name"), &SteamServer::getIPv4);
	ClassDB::bind_method(D_METHOD("getPSNID", "reference_name"), &SteamServer::getPSNID);
	ClassDB::bind_method(D_METHOD("getStadiaID", "reference_name"), &SteamServer::getStadiaID);
	ClassDB::bind_method(D_METHOD("getXboxPairwiseID", "reference_name"), &SteamServer::getXboxPairwiseID);
	ClassDB::bind_method(D_METHOD("isAddressLocalHost", "reference_name"), &SteamServer::isAddressLocalHost);
	ClassDB::bind_method(D_METHOD("isIdentityInvalid", "reference_name"), &SteamServer::isIdentityInvalid);
	ClassDB::bind_method(D_METHOD("isIdentityLocalHost", "reference_name"), &SteamServer::isIdentityLocalHost);
	ClassDB::bind_method(D_METHOD("isIPv4", "reference_name"), &SteamServer::isIPv4);
	ClassDB::bind_method(D_METHOD("isIPv6AllZeros", "reference_name"), &SteamServer::isIPv6AllZeros);
	ClassDB::bind_method(D_METHOD("parseIdentityString", "reference_name", "string_to_parse"), &SteamServer::parseIdentityString);
	ClassDB::bind_method(D_METHOD("parseIPAddressString", "reference_name", "string_to_parse"), &SteamServer::parseIPAddressString);
	ClassDB::bind_method(D_METHOD("setGenericBytes", "reference_name", "data"), &SteamServer::setGenericBytes);
	ClassDB::bind_method(D_METHOD("setGenericString", "reference_name", "this_string"), &SteamServer::setGenericString);
	ClassDB::bind_method(D_METHOD("setIdentityIPAddr", "reference_name", "ip_address_name"), &SteamServer::setIdentityIPAddr);
	ClassDB::bind_method(D_METHOD("setIdentityLocalHost", "reference_name"), &SteamServer::setIdentityLocalHost);
	ClassDB::bind_method(D_METHOD("setIdentitySteamID", "reference_name", "steam_id"), &SteamServer::setIdentitySteamID);
	ClassDB::bind_method(D_METHOD("setIdentitySteamID64", "reference_name", "steam_id"), &SteamServer::setIdentitySteamID64);
	ClassDB::bind_method(D_METHOD("setIPv4", "reference_name", "ip", "port"), &SteamServer::setIPv4);
	ClassDB::bind_method(D_METHOD("setIPv6", "reference_name", "ipv6", "port"), &SteamServer::setIPv6);
	ClassDB::bind_method(D_METHOD("setIPv6LocalHost", "reference_name", "port"), &SteamServer::setIPv6LocalHost, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("setPSNID", "reference_name", "psn_id"), &SteamServer::setPSNID);
	ClassDB::bind_method(D_METHOD("setStadiaID", "reference_name", "stadia_id"), &SteamServer::setStadiaID);
	ClassDB::bind_method(D_METHOD("setXboxPairwiseID", "reference_name", "xbox_id"), &SteamServer::setXboxPairwiseID); 
	ClassDB::bind_method(D_METHOD("toIdentityString", "reference_name"), &SteamServer::toIdentityString);
	ClassDB::bind_method(D_METHOD("toIPAddressString", "reference_name", "with_port"), &SteamServer::toIPAddressString);
	
	// NETWORKING UTILS BIND METHODS ////////////
	ClassDB::bind_method(D_METHOD("checkPingDataUpToDate", "max_age_in_seconds"), &SteamServer::checkPingDataUpToDate);
	ClassDB::bind_method(D_METHOD("convertPingLocationToString", "location"), &SteamServer::convertPingLocationToString);
	ClassDB::bind_method(D_METHOD("estimatePingTimeBetweenTwoLocations", "location1", "location2"), &SteamServer::estimatePingTimeBetweenTwoLocations);
	ClassDB::bind_method(D_METHOD("estimatePingTimeFromLocalHost", "location"), &SteamServer::estimatePingTimeFromLocalHost);
	ClassDB::bind_method(D_METHOD("getConfigValue", "config_value", "scope_type", "connection_handle"), &SteamServer::getConfigValue);
	ClassDB::bind_method(D_METHOD("getConfigValueInfo", "config_value"), &SteamServer::getConfigValueInfo);
	ClassDB::bind_method(D_METHOD("getDirectPingToPOP", "pop_id"), &SteamServer::getDirectPingToPOP);
	ClassDB::bind_method(D_METHOD("getLocalPingLocation"), &SteamServer::getLocalPingLocation);
	ClassDB::bind_method(D_METHOD("getLocalTimestamp"), &SteamServer::getLocalTimestamp);
	ClassDB::bind_method(D_METHOD("getPingToDataCenter", "pop_id"), &SteamServer::getPingToDataCenter);
	ClassDB::bind_method(D_METHOD("getPOPCount"), &SteamServer::getPOPCount);
	ClassDB::bind_method(D_METHOD("getPOPList"), &SteamServer::getPOPList);
	ClassDB::bind_method(D_METHOD("getRelayNetworkStatus"), &SteamServer::getRelayNetworkStatus);
	ClassDB::bind_method(D_METHOD("initRelayNetworkAccess"), &SteamServer::initRelayNetworkAccess);
	ClassDB::bind_method(D_METHOD("parsePingLocationString", "string"), &SteamServer::parsePingLocationString);
	ClassDB::bind_method(D_METHOD("setConnectionConfigValueFloat", "connection", "config", "value"), &SteamServer::setConnectionConfigValueFloat);
	ClassDB::bind_method(D_METHOD("setConnectionConfigValueInt32", "connection", "config", "value"), &SteamServer::setConnectionConfigValueInt32);
	ClassDB::bind_method(D_METHOD("setConnectionConfigValueString", "connection", "config", "value"), &SteamServer::setConnectionConfigValueString);
//	ClassDB::bind_method(D_METHOD("setConfigValue", "setting", "scope_type", "connection_handle", "data_type", "value"), &SteamServer::setConfigValue);
	ClassDB::bind_method(D_METHOD("setGlobalConfigValueFloat", "config", "value"), &SteamServer::setGlobalConfigValueFloat);
	ClassDB::bind_method(D_METHOD("setGlobalConfigValueInt32", "config", "value"), &SteamServer::setGlobalConfigValueInt32);
	ClassDB::bind_method(D_METHOD("setGlobalConfigValueString", "config", "value"), &SteamServer::setGlobalConfigValueString);

	// UGC BIND METHODS ////////////////////
	ClassDB::bind_method(D_METHOD("addAppDependency", "published_file_id", "app_id"), &SteamServer::addAppDependency);
	ClassDB::bind_method(D_METHOD("addContentDescriptor", "update_handle", "descriptor_id"), &SteamServer::addContentDescriptor);
	ClassDB::bind_method(D_METHOD("addDependency", "published_file_id", "child_published_file_id"), &SteamServer::addDependency);
	ClassDB::bind_method(D_METHOD("addExcludedTag", "query_handle", "tag_name"), &SteamServer::addExcludedTag);
	ClassDB::bind_method(D_METHOD("addItemKeyValueTag", "query_handle", "key", "value"), &SteamServer::addItemKeyValueTag);
	ClassDB::bind_method(D_METHOD("addItemPreviewFile", "query_handle", "preview_file", "type"), &SteamServer::addItemPreviewFile);
	ClassDB::bind_method(D_METHOD("addItemPreviewVideo", "query_handle", "video_id"), &SteamServer::addItemPreviewVideo);
	ClassDB::bind_method(D_METHOD("addItemToFavorites", "app_id", "published_file_id"), &SteamServer::addItemToFavorites);
	ClassDB::bind_method(D_METHOD("addRequiredKeyValueTag", "query_handle", "key", "value"), &SteamServer::addRequiredKeyValueTag);
	ClassDB::bind_method(D_METHOD("addRequiredTag", "query_handle", "tag_name"), &SteamServer::addRequiredTag);
	ClassDB::bind_method(D_METHOD("addRequiredTagGroup", "query_handle", "tag_array"), &SteamServer::addRequiredTagGroup);
	ClassDB::bind_method(D_METHOD("initWorkshopForGameServer", "workshop_depot_id"), &SteamServer::initWorkshopForGameServer);
	ClassDB::bind_method(D_METHOD("createItem", "app_id", "file_type"), &SteamServer::createItem);
	ClassDB::bind_method(D_METHOD("createQueryAllUGCRequest", "query_type", "matching_type", "creator_id", "consumer_id", "page"), &SteamServer::createQueryAllUGCRequest);
	ClassDB::bind_method(D_METHOD("createQueryUGCDetailsRequest", "published_file_id"), &SteamServer::createQueryUGCDetailsRequest);
	ClassDB::bind_method(D_METHOD("createQueryUserUGCRequest", "account_id", "list_type", "matching_ugc_type", "sort_order", "creator_id", "consumer_id", "page"), &SteamServer::createQueryUserUGCRequest);
	ClassDB::bind_method(D_METHOD("deleteItem", "published_file_id"), &SteamServer::deleteItem);
	ClassDB::bind_method(D_METHOD("downloadItem", "published_file_id", "high_priority"), &SteamServer::downloadItem);
	ClassDB::bind_method(D_METHOD("getItemDownloadInfo", "published_file_id"), &SteamServer::getItemDownloadInfo);
	ClassDB::bind_method(D_METHOD("getItemInstallInfo", "published_file_id"), &SteamServer::getItemInstallInfo);
	ClassDB::bind_method(D_METHOD("getItemState", "published_file_id"), &SteamServer::getItemState);
	ClassDB::bind_method(D_METHOD("getItemUpdateProgress", "update_handle"), &SteamServer::getItemUpdateProgress);
	ClassDB::bind_method(D_METHOD("getNumSubscribedItems"), &SteamServer::getNumSubscribedItems);
	ClassDB::bind_method(D_METHOD("getQueryUGCAdditionalPreview", "query_handle", "index", "preview_index"), &SteamServer::getQueryUGCAdditionalPreview);
	ClassDB::bind_method(D_METHOD("getQueryUGCChildren", "query_handle", "index", "child_count"), &SteamServer::getQueryUGCChildren);
	ClassDB::bind_method(D_METHOD("getQueryUGCContentDescriptors", "query_handle", "index", "max_entries"), &SteamServer::getQueryUGCContentDescriptors);
	ClassDB::bind_method(D_METHOD("getQueryUGCKeyValueTag", "query_handle", "index", "key_value_tag_index"), &SteamServer::getQueryUGCKeyValueTag);
	ClassDB::bind_method(D_METHOD("getQueryUGCMetadata", "query_handle", "index"), &SteamServer::getQueryUGCMetadata);
	ClassDB::bind_method(D_METHOD("getQueryUGCNumAdditionalPreviews", "query_handle", "index"), &SteamServer::getQueryUGCNumAdditionalPreviews);
	ClassDB::bind_method(D_METHOD("getQueryUGCNumKeyValueTags", "query_handle", "index"), &SteamServer::getQueryUGCNumKeyValueTags);
	ClassDB::bind_method(D_METHOD("getQueryUGCNumTags", "query_handle", "index"), &SteamServer::getQueryUGCNumTags);
	ClassDB::bind_method(D_METHOD("getQueryUGCPreviewURL", "query_handle", "index"), &SteamServer::getQueryUGCPreviewURL);
	ClassDB::bind_method(D_METHOD("getQueryUGCResult", "query_handle", "index"), &SteamServer::getQueryUGCResult);
	ClassDB::bind_method(D_METHOD("getQueryUGCStatistic", "query_handle", "index", "stat_type"), &SteamServer::getQueryUGCStatistic);
	ClassDB::bind_method(D_METHOD("getQueryUGCTag", "query_handle", "index", "tag_index"), &SteamServer::getQueryUGCTag);
	ClassDB::bind_method(D_METHOD("getQueryUGCTagDisplayName", "query_handle", "index", "tag_index"), &SteamServer::getQueryUGCTagDisplayName);
	ClassDB::bind_method(D_METHOD("getSubscribedItems"), &SteamServer::getSubscribedItems);
	ClassDB::bind_method(D_METHOD("getUserContentDescriptorPreferences", "max_entries"), &SteamServer::getUserContentDescriptorPreferences);
	ClassDB::bind_method(D_METHOD("getUserItemVote", "published_file_id"), &SteamServer::getUserItemVote);
	ClassDB::bind_method(D_METHOD("releaseQueryUGCRequest", "query_handle"), &SteamServer::releaseQueryUGCRequest);
	ClassDB::bind_method(D_METHOD("removeAppDependency", "published_file_id", "app_id"), &SteamServer::removeAppDependency);
	ClassDB::bind_method(D_METHOD("removeContentDescriptor", "update_handle", "descriptor_id"), &SteamServer::removeContentDescriptor);
	ClassDB::bind_method(D_METHOD("removeDependency", "published_file_id", "child_published_file_id"), &SteamServer::removeDependency);
	ClassDB::bind_method(D_METHOD("removeItemFromFavorites", "app_id", "published_file_id"), &SteamServer::removeItemFromFavorites);
	ClassDB::bind_method(D_METHOD("removeItemKeyValueTags", "update_handle", "key"), &SteamServer::removeItemKeyValueTags);
	ClassDB::bind_method(D_METHOD("removeItemPreview", "update_handle", "index"), &SteamServer::removeItemPreview);
	ClassDB::bind_method(D_METHOD("sendQueryUGCRequest", "update_handle"), &SteamServer::sendQueryUGCRequest);
	ClassDB::bind_method(D_METHOD("setAllowCachedResponse", "update_handle", "max_age_seconds"), &SteamServer::setAllowCachedResponse);
	ClassDB::bind_method(D_METHOD("setCloudFileNameFilter", "update_handle", "match_cloud_filename"), &SteamServer::setCloudFileNameFilter);
	ClassDB::bind_method(D_METHOD("setItemContent", "update_handle", "content_folder"), &SteamServer::setItemContent);
	ClassDB::bind_method(D_METHOD("setItemDescription", "update_handle", "description"), &SteamServer::setItemDescription);
	ClassDB::bind_method(D_METHOD("setItemMetadata", "update_handle", "metadata"), &SteamServer::setItemMetadata);
	ClassDB::bind_method(D_METHOD("setItemPreview", "update_handle", "preview_file"), &SteamServer::setItemPreview);
	ClassDB::bind_method(D_METHOD("setItemTags", "update_handle", "tag_array", "allow_admin_tags"), &SteamServer::setItemTags, DEFVAL(false));
	ClassDB::bind_method(D_METHOD("setItemTitle", "update_handle", "title"), &SteamServer::setItemTitle);
	ClassDB::bind_method(D_METHOD("setItemUpdateLanguage", "update_handle", "language"), &SteamServer::setItemUpdateLanguage);
	ClassDB::bind_method(D_METHOD("setItemVisibility", "update_handle", "visibility"), &SteamServer::setItemVisibility);
	ClassDB::bind_method(D_METHOD("setLanguage", "query_handle", "language"), &SteamServer::setLanguage);
	ClassDB::bind_method(D_METHOD("setMatchAnyTag", "query_handle", "match_any_tag"), &SteamServer::setMatchAnyTag);
	ClassDB::bind_method(D_METHOD("setRankedByTrendDays", "query_handle", "days"), &SteamServer::setRankedByTrendDays);
	ClassDB::bind_method(D_METHOD("setReturnAdditionalPreviews", "query_handle", "return_additional_previews"), &SteamServer::setReturnAdditionalPreviews);
	ClassDB::bind_method(D_METHOD("setReturnChildren", "query_handle", "return_children"), &SteamServer::setReturnChildren);
	ClassDB::bind_method(D_METHOD("setReturnKeyValueTags", "query_handle", "return_key_value_tags"), &SteamServer::setReturnKeyValueTags);
	ClassDB::bind_method(D_METHOD("setReturnLongDescription", "query_handle", "return_long_description"), &SteamServer::setReturnLongDescription);
	ClassDB::bind_method(D_METHOD("setReturnMetadata", "query_handle", "return_metadata"), &SteamServer::setReturnMetadata);
	ClassDB::bind_method(D_METHOD("setReturnOnlyIDs", "query_handle", "return_only_ids"), &SteamServer::setReturnOnlyIDs);
	ClassDB::bind_method(D_METHOD("setReturnPlaytimeStats", "query_handle", "days"), &SteamServer::setReturnPlaytimeStats);
	ClassDB::bind_method(D_METHOD("setReturnTotalOnly", "query_handle", "return_total_only"), &SteamServer::setReturnTotalOnly);
	ClassDB::bind_method(D_METHOD("setSearchText", "query_handle", "search_text"), &SteamServer::setSearchText);
	ClassDB::bind_method(D_METHOD("setUserItemVote", "published_file_id", "vote_up"), &SteamServer::setUserItemVote);
	ClassDB::bind_method(D_METHOD("startItemUpdate", "app_id", "file_id"), &SteamServer::startItemUpdate);
	ClassDB::bind_method(D_METHOD("startPlaytimeTracking", "published_file_ids"), &SteamServer::startPlaytimeTracking);
	ClassDB::bind_method(D_METHOD("stopPlaytimeTracking", "published_file_ids"), &SteamServer::stopPlaytimeTracking);
	ClassDB::bind_method(D_METHOD("stopPlaytimeTrackingForAllItems"), &SteamServer::stopPlaytimeTrackingForAllItems);
	ClassDB::bind_method(D_METHOD("getAppDependencies", "published_file_id"), &SteamServer::getAppDependencies);
	ClassDB::bind_method(D_METHOD("submitItemUpdate", "update_handle", "change_note"), &SteamServer::submitItemUpdate);
	ClassDB::bind_method(D_METHOD("subscribeItem", "published_file_id"), &SteamServer::subscribeItem);
	ClassDB::bind_method(D_METHOD("suspendDownloads", "suspend"), &SteamServer::suspendDownloads);
	ClassDB::bind_method(D_METHOD("unsubscribeItem", "published_file_id"), &SteamServer::unsubscribeItem);
	ClassDB::bind_method(D_METHOD("updateItemPreviewFile", "update_handle", "index", "preview_file"), &SteamServer::updateItemPreviewFile);
	ClassDB::bind_method(D_METHOD("updateItemPreviewVideo", "update_handle", "index", "video_id"), &SteamServer::updateItemPreviewVideo);
	ClassDB::bind_method(D_METHOD("showWorkshopEULA"), &SteamServer::showWorkshopEULA);	
	ClassDB::bind_method(D_METHOD("getWorkshopEULAStatus"), &SteamServer::getWorkshopEULAStatus);
	ClassDB::bind_method(D_METHOD("setTimeCreatedDateRange", "update_handle", "start", "end"), &SteamServer::setTimeCreatedDateRange);
	ClassDB::bind_method(D_METHOD("setTimeUpdatedDateRange", "update_handle", "start", "end"), &SteamServer::setTimeUpdatedDateRange);


	/////////////////////////////////////////////
	// CALLBACK SIGNAL BINDS ////////////////////
	/////////////////////////////////////////////
	//
	// STEAMWORKS SIGNALS ///////////////////////
	ADD_SIGNAL(MethodInfo("steamworks_error", PropertyInfo(Variant::STRING, "failed_signal"), PropertyInfo(Variant::STRING, "io failure")));

	// GAME SERVER SIGNALS //////////////////////
	ADD_SIGNAL(MethodInfo("associate_clan", PropertyInfo(Variant::INT, "result")));
	ADD_SIGNAL(MethodInfo("client_approved", PropertyInfo(Variant::INT, "steam_id"), PropertyInfo(Variant::INT, "owner_id")));
	ADD_SIGNAL(MethodInfo("client_denied", PropertyInfo(Variant::INT, "steam_id"), PropertyInfo(Variant::INT, "reason")));
	ADD_SIGNAL(MethodInfo("client_group_status", PropertyInfo(Variant::INT, "steam_id"), PropertyInfo(Variant::INT, "group_id"), PropertyInfo(Variant::BOOL, "member"), PropertyInfo(Variant::BOOL, "officer")));
	ADD_SIGNAL(MethodInfo("client_kick", PropertyInfo(Variant::INT, "steam_id"), PropertyInfo(Variant::INT, "reason")));
	ADD_SIGNAL(MethodInfo("policy_response", PropertyInfo(Variant::INT, "secure")));
	ADD_SIGNAL(MethodInfo("player_compat", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "players_dont_like_candidate"), PropertyInfo(Variant::INT, "players_candidate_doesnt_like"), PropertyInfo(Variant::INT, "clan_players_dont_like_candidate"), PropertyInfo(Variant::INT, "steam_id")));
	ADD_SIGNAL(MethodInfo("server_connect_failure", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::BOOL, "retrying")));
	ADD_SIGNAL(MethodInfo("server_connected"));
	ADD_SIGNAL(MethodInfo("server_disconnected", PropertyInfo(Variant::INT, "result")));
	
	// GAME SERVER STATS SIGNALS ////////////////
	ADD_SIGNAL(MethodInfo("stats_received", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "steam_id")));
	ADD_SIGNAL(MethodInfo("stats_stored", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "steam_id")));
	ADD_SIGNAL(MethodInfo("stats_unloaded", PropertyInfo(Variant::INT, "steam_id")));

	// HTTP SIGNALS /////////////////////////////
	ADD_SIGNAL(MethodInfo("http_request_completed", PropertyInfo(Variant::INT, "cookie_handle"), PropertyInfo(Variant::INT, "context_value"), PropertyInfo(Variant::BOOL, "request_success"), PropertyInfo(Variant::INT, "status_code"), PropertyInfo(Variant::INT, "body_size")));
	ADD_SIGNAL(MethodInfo("http_request_data_received", PropertyInfo(Variant::INT, "cookie_handle"), PropertyInfo(Variant::INT, "context_value"), PropertyInfo(Variant::INT, "offset"), PropertyInfo(Variant::INT, "bytes_received")));
	ADD_SIGNAL(MethodInfo("http_request_headers_received", PropertyInfo(Variant::INT, "cookie_handle"), PropertyInfo(Variant::INT, "context_value")));

	// INVENTORY SIGNALS ////////////////////////
	ADD_SIGNAL(MethodInfo("inventory_definition_update", PropertyInfo(Variant::ARRAY, "definitions")));
	ADD_SIGNAL(MethodInfo("inventory_eligible_promo_item", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::BOOL, "cached"), PropertyInfo(Variant::ARRAY, "definitions")));
	ADD_SIGNAL(MethodInfo("inventory_full_update", PropertyInfo(Variant::INT, "inventory_handle")));
	ADD_SIGNAL(MethodInfo("inventory_result_ready", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "inventory_handle")));
	ADD_SIGNAL(MethodInfo("inventory_start_purchase_result", PropertyInfo(Variant::STRING, "result"), PropertyInfo(Variant::INT, "order_id"), PropertyInfo(Variant::INT, "transaction_id")));
	ADD_SIGNAL(MethodInfo("inventory_request_prices_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::STRING, "currency")));

	// NETWORKING SIGNALS ///////////////////////
	ADD_SIGNAL(MethodInfo("p2p_session_request", PropertyInfo(Variant::INT, "steam_id_remote")));
	ADD_SIGNAL(MethodInfo("p2p_session_connect_fail", PropertyInfo(Variant::INT, "steam_id_remote"), PropertyInfo(Variant::INT, "session_error")));

	// NETWORKING MESSAGES //////////////////////
	ADD_SIGNAL(MethodInfo("network_messages_session_request", PropertyInfo(Variant::STRING, "identity")));
	ADD_SIGNAL(MethodInfo("network_messages_session_failed", PropertyInfo(Variant::INT, "reason")));

	// NETWORKING SOCKETS SIGNALS ///////////////
	ADD_SIGNAL(MethodInfo("network_connection_status_changed", PropertyInfo(Variant::INT, "connect_handle"), PropertyInfo(Variant::DICTIONARY, "connection"), PropertyInfo(Variant::INT, "old_state")));
	ADD_SIGNAL(MethodInfo("network_authentication_status", PropertyInfo(Variant::INT, "available"), PropertyInfo(Variant::STRING, "debug_message")));
	ADD_SIGNAL(MethodInfo("fake_ip_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::STRING, "identity"), PropertyInfo(Variant::STRING, "fake_ip"), PropertyInfo(Variant::ARRAY, "port_list")));

	// NETWORKING UTILS SIGNALS /////////////////
	ADD_SIGNAL(MethodInfo("relay_network_status", PropertyInfo(Variant::INT, "available"), PropertyInfo(Variant::INT, "ping_measurement"), PropertyInfo(Variant::INT, "available_config"), PropertyInfo(Variant::INT, "available_relay"), PropertyInfo(Variant::STRING, "debug_message")));

	// REMOTE STORAGE SIGNALS ///////////////////
	ADD_SIGNAL(MethodInfo("download_ugc_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::DICTIONARY, "download_data")));
	ADD_SIGNAL(MethodInfo("unsubscribe_item", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id")));
	ADD_SIGNAL(MethodInfo("subscribe_item", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id")));

	// UGC SIGNALS //////////////////////////////
	ADD_SIGNAL(MethodInfo("add_app_dependency_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::INT, "app_id")));
	ADD_SIGNAL(MethodInfo("add_ugc_dependency_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::INT, "child_id")));
	ADD_SIGNAL(MethodInfo("item_created", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::BOOL, "accept_tos")));
	ADD_SIGNAL(MethodInfo("item_downloaded", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::INT, "app_id")));
	ADD_SIGNAL(MethodInfo("get_app_dependencies_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::INT, "app_dependencies"), PropertyInfo(Variant::INT, "total_app_dependencies")));
	ADD_SIGNAL(MethodInfo("item_deleted", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id")));
	ADD_SIGNAL(MethodInfo("get_item_vote_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::BOOL, "vote_up"), PropertyInfo(Variant::BOOL, "vote_down"), PropertyInfo(Variant::BOOL, "vote_skipped")));
	ADD_SIGNAL(MethodInfo("item_installed", PropertyInfo(Variant::INT, "app_id"), PropertyInfo(Variant::INT, "file_id")));
	ADD_SIGNAL(MethodInfo("remove_app_dependency_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::INT, "app_id")));
	ADD_SIGNAL(MethodInfo("remove_ugc_dependency_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::INT, "child_id")));
	ADD_SIGNAL(MethodInfo("set_user_item_vote", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::BOOL, "vote_up")));
	ADD_SIGNAL(MethodInfo("start_playtime_tracking", PropertyInfo(Variant::INT, "result")));
	ADD_SIGNAL(MethodInfo("ugc_query_completed", PropertyInfo(Variant::INT, "handle"), PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "results_returned"), PropertyInfo(Variant::INT, "total_matching"), PropertyInfo(Variant::BOOL, "cached")));
	ADD_SIGNAL(MethodInfo("stop_playtime_tracking", PropertyInfo(Variant::INT, "result")));
	ADD_SIGNAL(MethodInfo("item_updated", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::BOOL, "accept_tos")));
	ADD_SIGNAL(MethodInfo("user_favorite_items_list_changed", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::BOOL, "was_add_request")));
	ADD_SIGNAL(MethodInfo("workshop_eula_status", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "app_id"), PropertyInfo(Variant::DICTIONARY, "eula_data")));
	ADD_SIGNAL(MethodInfo("user_subscribed_items_list_changed", PropertyInfo(Variant::INT, "app_id")));

	
	/////////////////////////////////////////////
	// CONSTANT BINDS
	/////////////////////////////////////////////
	//
	// STEAM API CONSTANTS //////////////////////
	BIND_CONSTANT(API_CALL_INVALID); 													// 0x0
	BIND_CONSTANT(APP_ID_INVALID); 														// 0x0
	BIND_CONSTANT(AUTH_TICKET_INVALID);													// 0
	BIND_CONSTANT(DEPOT_ID_INVALID); 													// 0x0
	BIND_CONSTANT(GAME_EXTRA_INFO_MAX); 												// 64
	BIND_CONSTANT(INVALID_BREAKPAD_HANDLE);												// (BREAKPAD_HANDLE)0
	BIND_CONSTANT(STEAM_ACCOUNT_ID_MASK); 												// 0xFFFFFFFF
	BIND_CONSTANT(STEAM_ACCOUNT_INSTANCE_MASK); 										// 0x000FFFFF
	BIND_CONSTANT(STEAM_BUFFER_SIZE);													// 255
	BIND_CONSTANT(STEAM_LARGE_BUFFER_SIZE);												// 8160
	BIND_CONSTANT(STEAM_MAX_ERROR_MESSAGE);												// 1024
	BIND_CONSTANT(STEAM_USER_CONSOLE_INSTANCE); 										// 2
	BIND_CONSTANT(STEAM_USER_DESKTOP_INSTANCE); 										// 1
	BIND_CONSTANT(STEAM_USER_WEB_INSTANCE); 											// 4
	BIND_CONSTANT(QUERY_PORT_ERROR); 													// 0xFFFE
	BIND_CONSTANT(QUERY_PORT_NOT_INITIALIZED); 											// 0xFFFF
	
	// STEAM SERVER API CONSTANTS ///////////////
	BIND_CONSTANT(FLAG_ACTIVE);															// 0x01
	BIND_CONSTANT(FLAG_DEDICATED);														// 0x04
	BIND_CONSTANT(FLAG_LINUX);															// 0x08
	BIND_CONSTANT(FLAG_NONE);															// 0x00
	BIND_CONSTANT(FLAG_PASSWORDED);														// 0x10
	BIND_CONSTANT(FLAG_PRIVATE);														// 0x20
	BIND_CONSTANT(FLAG_SECURE);															// 0x02
	BIND_CONSTANT(QUERY_PORT_SHARED);													// 0xffff

	// HTTP CONSTANTS ///////////////////////////
	BIND_CONSTANT(INVALID_HTTPCOOKIE_HANDLE);											// 0
	BIND_CONSTANT(INVALID_HTTPREQUEST_HANDLE);											// 0

	// INVENTORY CONSTANTS //////////////////////
	BIND_CONSTANT(INVENTORY_RESULT_INVALID);											// -1
	BIND_CONSTANT(ITEM_INSTANCE_ID_INVALID);											// 0

	// UGC CONSTANTS ////////////////////////////
	BIND_CONSTANT(NUM_UGC_RESULTS_PER_PAGE); 											// 50
	BIND_CONSTANT(DEVELOPER_METADATA_MAX); 												// 5000
	BIND_CONSTANT(UGC_QUERY_HANDLE_INVALID); 											// 0xffffffffffffffffull
	BIND_CONSTANT(UGC_UPDATE_HANDLE_INVALID); 											// 0xffffffffffffffffull


	/////////////////////////////////////////////
	// ENUM CONSTANT BINDS //////////////////////
	/////////////////////////////////////////////
	//
	// AccountType Enums
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_INVALID);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_INDIVIDUAL);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_MULTISEAT);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_GAME_SERVER);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_ANON_GAME_SERVER);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_PENDING);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_CONTENT_SERVER);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_CLAN);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_CHAT);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_CONSOLE_USER);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_ANON_USER);
	BIND_ENUM_CONSTANT(ACCOUNT_TYPE_MAX);

	// AuthSessionResponse Enums
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_OK);
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_USER_NOT_CONNECTED_TO_STEAM);
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_NO_LICENSE_OR_EXPIRED);
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_VAC_BANNED);
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_LOGGED_IN_ELSEWHERE);
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_VAC_CHECK_TIMED_OUT);
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_AUTH_TICKET_CANCELED);
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_AUTH_TICKET_INVALID_ALREADY_USED);
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_AUTH_TICKET_INVALID);
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_PUBLISHER_ISSUED_BAN);
	BIND_ENUM_CONSTANT(AUTH_SESSION_RESPONSE_AUTH_TICKET_NETWORK_IDENTITY_FAILURE);

	// AvatarSizes Enums
	BIND_ENUM_CONSTANT(AVATAR_SMALL); 
	BIND_ENUM_CONSTANT(AVATAR_MEDIUM);
	BIND_ENUM_CONSTANT(AVATAR_LARGE);

	// BeginAuthSessionResult Enums
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_OK);
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_INVALID_TICKET);
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_DUPLICATE_REQUEST); 
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_INVALID_VERSION);
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_GAME_MISMATCH);
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_EXPIRED_TICKET);

	// CommunityProfileItemType Enums
	BIND_ENUM_CONSTANT(PROFILE_ITEM_TYPE_ANIMATED_AVATAR);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_TYPE_AVATAR_FRAME);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_TYPE_PROFILE_MODIFIER);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_TYPE_PROFILE_BACKGROUND);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_TYPE_MINI_PROFILE_BACKGROUND);

	// CommunityProfileItemProperty Enums
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_IMAGE_SMALL);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_IMAGE_LARGE);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_INTERNAL_NAME);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_TITLE);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_DESCRIPTION);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_APP_ID);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_TYPE_ID);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_CLASS);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_MOVIE_WEBM);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_MOVIE_MP4);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_MOVIE_WEBM_SMALL);
	BIND_ENUM_CONSTANT(PROFILE_ITEM_PROPERTY_MOVIE_MP4_SMALL);

	// DenyReason Enums
	BIND_ENUM_CONSTANT(DENY_INVALID);
	BIND_ENUM_CONSTANT(DENY_INVALID_VERSION);
	BIND_ENUM_CONSTANT(DENY_GENERIC);
	BIND_ENUM_CONSTANT(DENY_NOT_LOGGED_ON);
	BIND_ENUM_CONSTANT(DENY_NO_LICENSE);
	BIND_ENUM_CONSTANT(DENY_CHEATER);
	BIND_ENUM_CONSTANT(DENY_LOGGED_IN_ELSEWHERE);
	BIND_ENUM_CONSTANT(DENY_UNKNOWN_TEXT);
	BIND_ENUM_CONSTANT(DENY_INCOMPATIBLE_ANTI_CHEAT);
	BIND_ENUM_CONSTANT(DENY_MEMORY_CORRUPTION);
	BIND_ENUM_CONSTANT(DENY_INCOMPATIBLE_SOFTWARE);
	BIND_ENUM_CONSTANT(DENY_STEAM_CONNECTION_LOST);
	BIND_ENUM_CONSTANT(DENY_STEAM_CONNECTION_ERROR);
	BIND_ENUM_CONSTANT(DENY_STEAM_RESPONSE_TIMED_OUT);
	BIND_ENUM_CONSTANT(DENY_STEAM_VALIDATION_STALLED);
	BIND_ENUM_CONSTANT(DENY_STEAM_OWNER_LEFT_GUEST_USER);

	// FilePathType Enums
	BIND_ENUM_CONSTANT(FILE_PATH_TYPE_INVALID);
	BIND_ENUM_CONSTANT(FILE_PATH_TYPE_ABSOLUTE);
	BIND_ENUM_CONSTANT(FILE_PATH_TYPE_API_FILENAME);

	// FriendFlags Enums
	BIND_BITFIELD_FLAG(FRIEND_FLAG_NONE);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_BLOCKED);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_FRIENDSHIP_REQUESTED);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_IMMEDIATE);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_CLAN_MEMBER);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_ON_GAME_SERVER);
	//	BIND_BITFIELD_FLAG(FRIEND_FLAG_HAS_PLAYED_WITH);
	//	BIND_BITFIELD_FLAG(FRIEND_FLAG_FRIEND_OF_FRIEND);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_REQUESTING_FRIENDSHIP);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_REQUESTING_INFO);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_IGNORED);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_IGNORED_FRIEND);
	//	BIND_BITFIELD_FLAG(FRIEND_FLAG_SUGGESTED);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_CHAT_MEMBER);
	BIND_BITFIELD_FLAG(FRIEND_FLAG_ALL);

	// FriendRelationship Enums
	BIND_ENUM_CONSTANT(FRIEND_RELATION_NONE);
	BIND_ENUM_CONSTANT(FRIEND_RELATION_BLOCKED);
	BIND_ENUM_CONSTANT(FRIEND_RELATION_REQUEST_RECIPIENT);
	BIND_ENUM_CONSTANT(FRIEND_RELATION_FRIEND);
	BIND_ENUM_CONSTANT(FRIEND_RELATION_REQUEST_INITIATOR);
	BIND_ENUM_CONSTANT(FRIEND_RELATION_IGNORED);
	BIND_ENUM_CONSTANT(FRIEND_RELATION_IGNORED_FRIEND);
	BIND_ENUM_CONSTANT(FRIEND_RELATION_SUGGESTED);
	BIND_ENUM_CONSTANT(FRIEND_RELATION_MAX);

	// GameIDType Enums
	BIND_ENUM_CONSTANT(GAME_TYPE_APP);
	BIND_ENUM_CONSTANT(GAME_TYPE_GAME_MOD);
	BIND_ENUM_CONSTANT(GAME_TYPE_SHORTCUT);
	BIND_ENUM_CONSTANT(GAME_TYPE_P2P);

	// HTTPMethod Enums
	BIND_ENUM_CONSTANT(HTTP_METHOD_INVALID);
	BIND_ENUM_CONSTANT(HTTP_METHOD_GET);
	BIND_ENUM_CONSTANT(HTTP_METHOD_HEAD);
	BIND_ENUM_CONSTANT(HTTP_METHOD_POST);
	BIND_ENUM_CONSTANT(HTTP_METHOD_PUT);
	BIND_ENUM_CONSTANT(HTTP_METHOD_DELETE);
	BIND_ENUM_CONSTANT(HTTP_METHOD_OPTIONS);
	BIND_ENUM_CONSTANT(HTTP_METHOD_PATCH);

	// HTTPStatusCode Enums
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_INVALID);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_100_CONTINUE);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_101_SWITCHING_PROTOCOLS);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_200_OK);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_201_CREATED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_202_ACCEPTED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_203_NON_AUTHORITATIVE);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_204_NO_CONTENT);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_205_RESET_CONTENT);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_206_PARTIAL_CONTENT);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_300_MULTIPLE_CHOICES);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_301_MOVED_PERMANENTLY);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_302_FOUND);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_303_SEE_OTHER);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_304_NOT_MODIFIED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_305_USE_PROXY);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_307_TEMPORARY_REDIRECT);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_308_PERMANENT_REDIRECT);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_400_BAD_REQUEST);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_401_UNAUTHORIZED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_402_PAYMENT_REQUIRED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_403_FORBIDDEN);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_404_NOT_FOUND);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_405_METHOD_NOT_ALLOWED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_406_NOT_ACCEPTABLE);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_407_PROXY_AUTH_REQUIRED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_408_REQUEST_TIMEOUT);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_409_CONFLICT);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_410_GONE);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_411_LENGTH_REQUIRED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_412_PRECONDITION_FAILED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_413_REQUEST_ENTITY_TOO_LARGE);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_414_REQUEST_URI_TOO_LONG);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_415_UNSUPPORTED_MEDIA_TYPE);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_416_REQUESTED_RANGE_NOT_SATISFIABLE);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_417_EXPECTATION_FAILED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_4XX_UNKNOWN);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_429_TOO_MANY_REQUESTS);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_444_CONNECTION_CLOSED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_501_NOT_IMPLEMENTED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_502_BAD_GATEWAY);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_503_SERVICE_UNAVAILABLE);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_504_GATEWAY_TIMEOUT);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_505_HTTP_VERSION_NOT_SUPPORTED);
	BIND_ENUM_CONSTANT(HTTP_STATUS_CODE_5XX_UNKNOWN);

	// ItemFlags Enums
	BIND_BITFIELD_FLAG(STEAM_ITEM_NO_TRADE);
	BIND_BITFIELD_FLAG(STEAM_ITEM_REMOVED);
	BIND_BITFIELD_FLAG(STEAM_ITEM_CONSUMED);

	// ItemPreviewType Enums
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_IMAGE);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_YOUTUBE_VIDEO);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_SKETCHFAB);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_ENVIRONMENTMAP_HORIZONTAL_CROSS);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_ENVIRONMENTMAP_LAT_LONG);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_RESERVED_MAX);

	// ItemState Enums
	BIND_BITFIELD_FLAG(ITEM_STATE_NONE);
	BIND_BITFIELD_FLAG(ITEM_STATE_SUBSCRIBED);
	BIND_BITFIELD_FLAG(ITEM_STATE_LEGACY_ITEM);
	BIND_BITFIELD_FLAG(ITEM_STATE_INSTALLED);
	BIND_BITFIELD_FLAG(ITEM_STATE_NEEDS_UPDATE);
	BIND_BITFIELD_FLAG(ITEM_STATE_DOWNLOADING);
	BIND_BITFIELD_FLAG(ITEM_STATE_DOWNLOAD_PENDING);

	// ItemStatistic Enums
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_SUBSCRIPTIONS);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_FAVORITES);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_FOLLOWERS);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_UNIQUE_SUBSCRIPTIONS);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_UNIQUE_FAVORITES);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_UNIQUE_FOLLOWERS);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_UNIQUE_WEBSITE_VIEWS);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_REPORT_SCORE);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_SECONDS_PLAYED);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_PLAYTIME_SESSIONS);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_COMMENTS);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_SECONDS_PLAYED_DURING_TIME_PERIOD);
	BIND_ENUM_CONSTANT(ITEM_STATISTIC_NUM_PLAYTIME_SESSIONS_DURING_TIME_PERIOD);

	// ItemUpdateStatus Enums
	BIND_ENUM_CONSTANT(ITEM_UPDATE_STATUS_INVALID);
	BIND_ENUM_CONSTANT(ITEM_UPDATE_STATUS_PREPARING_CONFIG);
	BIND_ENUM_CONSTANT(ITEM_UPDATE_STATUS_PREPARING_CONTENT);
	BIND_ENUM_CONSTANT(ITEM_UPDATE_STATUS_UPLOADING_CONTENT);
	BIND_ENUM_CONSTANT(ITEM_UPDATE_STATUS_UPLOADING_PREVIEW_FILE);
	BIND_ENUM_CONSTANT(ITEM_UPDATE_STATUS_COMMITTING_CHANGES);

	// LocalFileChange Enums
	BIND_ENUM_CONSTANT(LOCAL_FILE_CHANGE_INVALID);
	BIND_ENUM_CONSTANT(LOCAL_FILE_CHANGE_FILE_UPDATED);
	BIND_ENUM_CONSTANT(LOCAL_FILE_CHANGE_FILE_DELETED);

	// NetworkingAvailability Enums
	BIND_ENUM_CONSTANT(NETWORKING_AVAILABILITY_CANNOT_TRY);
	BIND_ENUM_CONSTANT(NETWORKING_AVAILABILITY_FAILED);
	BIND_ENUM_CONSTANT(NETWORKING_AVAILABILITY_PREVIOUSLY);
	BIND_ENUM_CONSTANT(NETWORKING_AVAILABILITY_RETRYING);
	BIND_ENUM_CONSTANT(NETWORKING_AVAILABILITY_NEVER_TRIED);
	BIND_ENUM_CONSTANT(NETWORKING_AVAILABILITY_WAITING);
	BIND_ENUM_CONSTANT(NETWORKING_AVAILABILITY_ATTEMPTING);
	BIND_ENUM_CONSTANT(NETWORKING_AVAILABILITY_CURRENT);
	BIND_ENUM_CONSTANT(NETWORKING_AVAILABILITY_UNKNOWN);
	BIND_ENUM_CONSTANT(NETWORKING_AVAILABILITY_FORCE_32BIT);

	// NetworkingConfigDataType Enums
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_TYPE_INT32);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_TYPE_INT64);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_TYPE_FLOAT); 
	BIND_ENUM_CONSTANT(ETWORKING_CONFIG_TYPE_STRING);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_TYPE_FUNCTION_PTR);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_TYPE_FORCE_32BIT);

	// NetworkingConfigScope Enums
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SCOPE_GLOBAL);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SCOPE_SOCKETS_INTERFACE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SCOPE_LISTEN_SOCKET);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SCOPE_CONNECTION);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SCOPE_FORCE_32BIT);

	// NetworkingConfigValue Enums
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_INVALID);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_PACKET_LOSS_SEND);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_PACKET_LOSS_RECV);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_PACKET_LAG_SEND);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_PACKET_LAG_RECV);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_PACKET_REORDER_SEND);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_PACKET_REORDER_RECV);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_PACKET_REORDER_TIME);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_PACKET_DUP_SEND);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_PACKET_DUP_REVC);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_PACKET_DUP_TIME_MAX);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_PACKET_TRACE_MAX_BYTES);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_RATE_LIMIT_SEND_RATE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_RATE_LIMIT_SEND_BURST);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_RATE_LIMIT_RECV_RATE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_FAKE_RATE_LIMIT_RECV_BURST);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_CONNECTION_USER_DATA);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_TIMEOUT_INITIAL);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_TIMEOUT_CONNECTED);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SEND_BUFFER_SIZE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_RECV_BUFFER_SIZE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_RECV_BUFFER_MESSAGES);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_RECV_MAX_MESSAGE_SIZE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_RECV_MAX_SEGMENTS_PER_PACKET);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SEND_RATE_MIN);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SEND_RATE_MAX);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_NAGLE_TIME);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_IP_ALLOW_WITHOUT_AUTH);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_MTU_PACKET_SIZE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_MTU_DATA_SIZE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_UNENCRYPTED);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SYMMETRIC_CONNECT);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_LOCAL_VIRTUAL_PORT);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_DUAL_WIFI_ENABLE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_ENABLE_DIAGNOSTICS_UI);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_CONSEC_PING_TIMEOUT_FAIL_INITIAL);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_CONSEC_PING_TIMEOUT_FAIL);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_MIN_PINGS_BEFORE_PING_ACCURATE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_SINGLE_SOCKET);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_FORCE_RELAY_CLUSTER);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_DEBUG_TICKET_ADDRESS);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_FORCE_PROXY_ADDR);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_FAKE_CLUSTER_PING);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_LOG_LEVEL_ACK_RTT);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_LOG_LEVEL_PACKET_DECODE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_LOG_LEVEL_MESSAGE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_LOG_LEVEL_PACKET_GAPS);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_LOG_LEVEL_P2P_RENDEZVOUS);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_LOG_LEVEL_SRD_RELAY_PINGS);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_CALLBACK_CONNECTION_STATUS_CHANGED);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_CALLBACK_AUTH_STATUS_CHANGED);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_CALLBACK_RELAY_NETWORK_STATUS_CHANGED);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_CALLBACK_MESSAGE_SESSION_REQUEST);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_CALLBACK_MESSAGES_SESSION_FAILED);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_CALLBACK_CREATE_CONNECTION_SIGNALING);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_CALLBACK_FAKE_IP_RESULT);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_P2P_STUN_SERVER_LIST);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_ICE_ENABLE);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_ICE_PENALTY);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_SDR_PENALTY);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_P2P_TURN_SERVER_LIST);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_P2P_TURN_uSER_LIST);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_P2P_TURN_PASS_LIST);
//	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_LAN_BEACON_PENALTY);		// Commented out in the SDK
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_ICE_IMPLEMENTATION);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_VALUE_FORCE32BIT);

	// NetworkingConnectionEnd Enums
	BIND_ENUM_CONSTANT(CONNECTION_END_INVALID);
	BIND_ENUM_CONSTANT(CONNECTION_END_APP_MIN);
	BIND_ENUM_CONSTANT(CONNECTION_END_APP_GENERIC);
	BIND_ENUM_CONSTANT(CONNECTION_END_APP_MAX);
	BIND_ENUM_CONSTANT(CONNECTION_END_APP_EXCEPTION_MIN);
	BIND_ENUM_CONSTANT(CONNECTION_END_APP_EXCEPTION_GENERIC);
	BIND_ENUM_CONSTANT(CONNECTION_END_APP_EXCEPTION_MAX);
	BIND_ENUM_CONSTANT(CONNECTION_END_LOCAL_MIN);
	BIND_ENUM_CONSTANT(CONNECTION_END_LOCAL_OFFLINE_MODE);
	BIND_ENUM_CONSTANT(CONNECTION_END_LOCAL_MANY_RELAY_CONNECTIVITY);
	BIND_ENUM_CONSTANT(CONNECTION_END_LOCAL_HOSTED_SERVER_PRIMARY_RELAY);
	BIND_ENUM_CONSTANT(CONNECTION_END_LOCAL_NETWORK_CONFIG);
	BIND_ENUM_CONSTANT(CONNECTION_END_LOCAL_RIGHTS);
	BIND_ENUM_CONSTANT(CONNECTION_END_NO_PUBLIC_ADDRESS);
	BIND_ENUM_CONSTANT(CONNECTION_END_LOCAL_MAX);
	BIND_ENUM_CONSTANT(CONNECTION_END_REMOVE_MIN);
	BIND_ENUM_CONSTANT(CONNECTION_END_REMOTE_TIMEOUT);
	BIND_ENUM_CONSTANT(CONNECTION_END_REMOTE_BAD_CRYPT);
	BIND_ENUM_CONSTANT(CONNECTION_END_REMOTE_BAD_CERT);
	BIND_ENUM_CONSTANT(CONNECTION_END_BAD_PROTOCOL_VERSION);
	BIND_ENUM_CONSTANT(CONNECTION_END_REMOTE_P2P_ICE_NO_PUBLIC_ADDRESSES);
	BIND_ENUM_CONSTANT(CONNECTION_END_REMOTE_MAX);
	BIND_ENUM_CONSTANT(CONNECTION_END_MISC_MIN);
	BIND_ENUM_CONSTANT(CONNECTION_END_MISC_GENERIC);
	BIND_ENUM_CONSTANT(CONNECTION_END_MISC_INTERNAL_ERROR);
	BIND_ENUM_CONSTANT(CONNECTION_END_MISC_TIMEOUT);
	BIND_ENUM_CONSTANT(CONNECTION_END_MISC_STEAM_CONNECTIVITY);
	BIND_ENUM_CONSTANT(CONNECTION_END_MISC_NO_RELAY_SESSIONS_TO_CLIENT);
	BIND_ENUM_CONSTANT(CONNECTION_END_MISC_P2P_RENDEZVOUS);
	BIND_ENUM_CONSTANT(CONNECTION_END_MISC_P2P_NAT_FIREWALL);
	BIND_ENUM_CONSTANT(CONNECTION_END_MISC_PEER_SENT_NO_CONNECTION);
	BIND_ENUM_CONSTANT(CONNECTION_END_MISC_MAX);
	BIND_ENUM_CONSTANT(CONNECTION_END_FORCE32BIT);

	// NetworkingConnectionState Enums
	BIND_ENUM_CONSTANT(CONNECTION_STATE_NONE);
	BIND_ENUM_CONSTANT(CONNECTION_STATE_CONNECTING);
	BIND_ENUM_CONSTANT(CONNECTION_STATE_FINDING_ROUTE);
	BIND_ENUM_CONSTANT(CONNECTION_STATE_CONNECTED);
	BIND_ENUM_CONSTANT(CONNECTION_STATE_CLOSED_BY_PEER);
	BIND_ENUM_CONSTANT(CONNECTION_STATE_PROBLEM_DETECTED_LOCALLY);
	BIND_ENUM_CONSTANT(CONNECTION_STATE_FIN_WAIT);
	BIND_ENUM_CONSTANT(CONNECTION_STATE_LINGER);
	BIND_ENUM_CONSTANT(CONNECTION_STATE_DEAD);
	BIND_ENUM_CONSTANT(CONNECTION_STATE_FORCE_32BIT);

	// NetworkingFakeIPType Enums
	BIND_ENUM_CONSTANT(FAKE_IP_TYPE_INVALID);
	BIND_ENUM_CONSTANT(FAKE_IP_TYPE_NOT_FAKE);
	BIND_ENUM_CONSTANT(FAKE_IP_TYPE_GLOBAL_IPV4);
	BIND_ENUM_CONSTANT(FAKE_IP_TYPE_LOCAL_IPV4);
	BIND_ENUM_CONSTANT(FAKE_IP_TYPE_FORCE32BIT);

	// NetworkingGetConfigValueResult Enums
	BIND_ENUM_CONSTANT(NETWORKING_GET_CONFIG_VALUE_BAD_VALUE);
	BIND_ENUM_CONSTANT(NETWORKING_GET_CONFIG_VALUE_BAD_SCOPE_OBJ);
	BIND_ENUM_CONSTANT(NETWORKING_GET_CONFIG_VALUE_BUFFER_TOO_SMALL);
	BIND_ENUM_CONSTANT(NETWORKING_GET_CONFIG_VALUE_OK);
	BIND_ENUM_CONSTANT(NETWORKING_GET_CONFIG_VALUE_OK_INHERITED);
	BIND_ENUM_CONSTANT(NETWORKING_GET_CONFIG_VALUE_FORCE_32BIT);

	// NetworkingIdentityType Enums
	BIND_ENUM_CONSTANT(IDENTITY_TYPE_INVALID);
	BIND_ENUM_CONSTANT(IDENTITY_TYPE_STEAMID);
	BIND_ENUM_CONSTANT(IDENTITY_TYPE_IP_ADDRESS);
	BIND_ENUM_CONSTANT(IDENTITY_TYPE_GENERIC_STRING);
	BIND_ENUM_CONSTANT(IDENTITY_TYPE_GENERIC_BYTES);
	BIND_ENUM_CONSTANT(IDENTITY_TYPE_UNKNOWN_TYPE);
	BIND_ENUM_CONSTANT(IDENTITY_TYPE_XBOX_PAIRWISE);
	BIND_ENUM_CONSTANT(IDENTITY_TYPE_SONY_PSN);
	BIND_ENUM_CONSTANT(IDENTITY_TYPE_GOOGLE_STADIA);
	//	BIND_ENUM_CONSTANT(IDENTITY_TYPE_NINTENDO);
	//	BIND_ENUM_CONSTANT(IDENTITY_TYPE_EPIC_GS);
	//	BIND_ENUM_CONSTANT(IDENTITY_TYPE_WEGAME);
	BIND_ENUM_CONSTANT(IDENTITY_TYPE_FORCE_32BIT);

	// NetworkingSocketsDebugOutputType Enums
	BIND_ENUM_CONSTANT(NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_NONE);
	BIND_ENUM_CONSTANT(NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_BUG);
	BIND_ENUM_CONSTANT(NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_ERROR);
	BIND_ENUM_CONSTANT(NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_IMPORTANT);
	BIND_ENUM_CONSTANT(NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_WARNING);
	BIND_ENUM_CONSTANT(NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_MSG);
	BIND_ENUM_CONSTANT(NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_VERBOSE);
	BIND_ENUM_CONSTANT(NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_DEBUG);
	BIND_ENUM_CONSTANT(NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_EVERYTHING);
	BIND_ENUM_CONSTANT(NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_FORCE_32BIT);

	// OverlayToStoreFlag Enums
	BIND_ENUM_CONSTANT(OVERLAY_TO_STORE_FLAG_NONE);
	BIND_ENUM_CONSTANT(OVERLAY_TO_STORE_FLAG_ADD_TO_CART);
	BIND_ENUM_CONSTANT(OVERLAY_TO_STORE_FLAG_AND_TO_CART_AND_SHOW);

	// OverlayToWebPageMode Enums
	BIND_ENUM_CONSTANT(OVERLAY_TO_WEB_PAGE_MODE_DEFAULT);
	BIND_ENUM_CONSTANT(OVERLAY_TO_WEB_PAGE_MODE_MODAL);

	// P2PSend Enums
	BIND_ENUM_CONSTANT(P2P_SEND_UNRELIABLE);
	BIND_ENUM_CONSTANT(P2P_SEND_UNRELIABLE_NO_DELAY);
	BIND_ENUM_CONSTANT(P2P_SEND_RELIABLE);
	BIND_ENUM_CONSTANT(P2P_SEND_RELIABLE_WITH_BUFFERING);

	// P2PSessionError Enums
	BIND_ENUM_CONSTANT(P2P_SESSION_ERROR_NONE);
	BIND_ENUM_CONSTANT(P2P_SESSION_ERROR_NOT_RUNNING_APP);
	BIND_ENUM_CONSTANT(P2P_SESSION_ERROR_NO_RIGHTS_TO_APP);
	BIND_ENUM_CONSTANT(P2P_SESSION_ERROR_DESTINATION_NOT_LOGGED_ON);
	BIND_ENUM_CONSTANT(P2P_SESSION_ERROR_TIMEOUT);
	BIND_ENUM_CONSTANT(P2P_SESSION_ERROR_MAX);

	// PersonaChange Enums
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_NAME);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_STATUS);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_COME_ONLINE);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_GONE_OFFLINE);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_GAME_PLAYED);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_GAME_SERVER);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_AVATAR);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_JOINED_SOURCE);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_LEFT_SOURCE);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_RELATIONSHIP_CHANGED);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_NAME_FIRST_SET);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_FACEBOOK_INFO);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_NICKNAME);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_STEAM_LEVEL);
	BIND_BITFIELD_FLAG(PERSONA_CHANGE_RICH_PRESENCE);

	// PersonaState Enums
	BIND_ENUM_CONSTANT(PERSONA_STATE_OFFLINE);
	BIND_ENUM_CONSTANT(PERSONA_STATE_ONLINE);
	BIND_ENUM_CONSTANT(PERSONA_STATE_BUSY);
	BIND_ENUM_CONSTANT(PERSONA_STATE_AWAY);
	BIND_ENUM_CONSTANT(PERSONA_STATE_SNOOZE);
	BIND_ENUM_CONSTANT(PERSONA_STATE_LOOKING_TO_TRADE);
	BIND_ENUM_CONSTANT(PERSONA_STATE_LOOKING_TO_PLAY);
	BIND_ENUM_CONSTANT(PERSONA_STATE_INVISIBLE);
	BIND_ENUM_CONSTANT(PERSONA_STATE_MAX);

	// RemoteStoragePlatform Enums
	BIND_BITFIELD_FLAG(REMOTE_STORAGE_PLATFORM_NONE);
	BIND_BITFIELD_FLAG(REMOTE_STORAGE_PLATFORM_WINDOWS);
	BIND_BITFIELD_FLAG(REMOTE_STORAGE_PLATFORM_OSX);
	BIND_BITFIELD_FLAG(REMOTE_STORAGE_PLATFORM_PS3);
	BIND_BITFIELD_FLAG(REMOTE_STORAGE_PLATFORM_LINUX);
	BIND_BITFIELD_FLAG(REMOTE_STORAGE_PLATFORM_SWITCH);
	BIND_BITFIELD_FLAG(REMOTE_STORAGE_PLATFORM_ANDROID);
	BIND_BITFIELD_FLAG(REMOTE_STORAGE_PLATFORM_IOS);
	BIND_BITFIELD_FLAG(REMOTE_STORAGE_PLATFORM_ALL);

	// RemoteStoragePublishedFileVisibility Enums
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PUBLISHED_VISIBILITY_PUBLIC);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PUBLISHED_VISIBILITY_FRIENDS_ONLY);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PUBLISHED_VISIBILITY_PRIVATE);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PUBLISHED_VISIBILITY_UNLISTED);

	// Result Enums
	BIND_ENUM_CONSTANT(RESULT_NONE);
	BIND_ENUM_CONSTANT(RESULT_OK);
	BIND_ENUM_CONSTANT(RESULT_FAIL);
	BIND_ENUM_CONSTANT(RESULT_NO_CONNECTION);
	BIND_ENUM_CONSTANT(RESULT_INVALID_PASSWORD);
	BIND_ENUM_CONSTANT(RESULT_LOGGED_IN_ELSEWHERE);
	BIND_ENUM_CONSTANT(RESULT_INVALID_PROTOCOL_VER);
	BIND_ENUM_CONSTANT(RESULT_INVALID_PARAM);
	BIND_ENUM_CONSTANT(RESULT_FILE_NOT_FOUND);
	BIND_ENUM_CONSTANT(RESULT_BUSY);
	BIND_ENUM_CONSTANT(RESULT_INVALID_STATE);
	BIND_ENUM_CONSTANT(RESULT_INVALID_NAME);
	BIND_ENUM_CONSTANT(RESULT_INVALID_EMAIL);
	BIND_ENUM_CONSTANT(RESULT_DUPLICATE_NAME);
	BIND_ENUM_CONSTANT(RESULT_ACCESS_DENIED);
	BIND_ENUM_CONSTANT(RESULT_TIMEOUT);
	BIND_ENUM_CONSTANT(RESULT_BANNED);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_NOT_FOUND);
	BIND_ENUM_CONSTANT(RESULT_INVALID_STEAMID);
	BIND_ENUM_CONSTANT(RESULT_SERVICE_UNAVAILABLE);
	BIND_ENUM_CONSTANT(RESULT_NOT_LOGGED_ON);
	BIND_ENUM_CONSTANT(RESULT_PENDING);
	BIND_ENUM_CONSTANT(RESULT_ENCRYPTION_FAILURE);
	BIND_ENUM_CONSTANT(RESULT_INSUFFICIENT_PRIVILEGE);
	BIND_ENUM_CONSTANT(RESULT_LIMIT_EXCEEDED);
	BIND_ENUM_CONSTANT(RESULT_REVOKED);
	BIND_ENUM_CONSTANT(RESULT_EXPIRED);
	BIND_ENUM_CONSTANT(RESULT_ALREADY_REDEEMED);
	BIND_ENUM_CONSTANT(RESULT_DUPLICATE_REQUEST);
	BIND_ENUM_CONSTANT(RESULT_ALREADY_OWNED);
	BIND_ENUM_CONSTANT(RESULT_IP_NOT_FOUND);
	BIND_ENUM_CONSTANT(RESULT_PERSIST_FAILED);
	BIND_ENUM_CONSTANT(RESULT_LOCKING_FAILED);
	BIND_ENUM_CONSTANT(RESULT_LOG_ON_SESSION_REPLACED);
	BIND_ENUM_CONSTANT(RESULT_CONNECT_FAILED);
	BIND_ENUM_CONSTANT(RESULT_HANDSHAKE_FAILED);
	BIND_ENUM_CONSTANT(RESULT_IO_FAILURE);
	BIND_ENUM_CONSTANT(RESULT_REMOTE_DISCONNECT);
	BIND_ENUM_CONSTANT(RESULT_SHOPPING_CART_NOT_FOUND);
	BIND_ENUM_CONSTANT(RESULT_BLOCKED);
	BIND_ENUM_CONSTANT(RESULT_IGNORED);
	BIND_ENUM_CONSTANT(RESULT_NO_MATCH);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_DISABLED);
	BIND_ENUM_CONSTANT(RESULT_SERVICE_READ_ONLY);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_NOT_FEATURED);
	BIND_ENUM_CONSTANT(RESULT_ADMINISTRATO_ROK);
	BIND_ENUM_CONSTANT(RESULT_CONTENT_VERSION);
	BIND_ENUM_CONSTANT(RESULT_TRY_ANOTHER_CM);
	BIND_ENUM_CONSTANT(RESULT_PASSWORD_REQUIRED_TO_KICK_SESSION);
	BIND_ENUM_CONSTANT(RESULT_ALREADY_LOGGED_IN_ELSEWHERE);
	BIND_ENUM_CONSTANT(RESULT_SUSPENDED);
	BIND_ENUM_CONSTANT(RESULT_CANCELLED);
	BIND_ENUM_CONSTANT(RESULT_DATA_CORRUPTION);
	BIND_ENUM_CONSTANT(RESULT_DISK_FULL);
	BIND_ENUM_CONSTANT(RESULT_REMOTE_CALL_FAILED);
	BIND_ENUM_CONSTANT(RESULT_PASSWORD_UNSET);
	BIND_ENUM_CONSTANT(RESULT_EXTERNAL_ACCOUNT_UNLINKED);
	BIND_ENUM_CONSTANT(RESULT_PSN_TICKET_INVALID);
	BIND_ENUM_CONSTANT(RESULT_EXTERNAL_ACCOUNT_ALREADY_LINKED);
	BIND_ENUM_CONSTANT(RESULT_REMOTE_FILE_CONFLICT);
	BIND_ENUM_CONSTANT(RESULT_ILLEGAL_PASSWORD);
	BIND_ENUM_CONSTANT(RESULT_SAME_AS_PREVIOUS_VALUE);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_LOG_ON_DENIED);
	BIND_ENUM_CONSTANT(RESULT_CANNOT_USE_OLD_PASSWORD);
	BIND_ENUM_CONSTANT(RESULT_INVALID_LOG_IN_AUTH_CODE);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_LOG_ON_DENIED_NO_MAIL);
	BIND_ENUM_CONSTANT(RESULT_HARDWARE_NOT_CAPABLE_OF_IPT);
	BIND_ENUM_CONSTANT(RESULT_IPT_INIT_ERROR);
	BIND_ENUM_CONSTANT(RESULT_PARENTAL_CONTROL_RESTRICTED);
	BIND_ENUM_CONSTANT(RESULT_FACEBOOK_QUERY_ERROR);
	BIND_ENUM_CONSTANT(RESULT_EXPIRED_LOGIN_AUTH_CODE);
	BIND_ENUM_CONSTANT(RESULT_IP_LOGIN_RESTRICTION_FAILED);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_LOCKED_DOWN);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_LOG_ON_DENIED_VERIFIED_EMAIL_REQUIRED);
	BIND_ENUM_CONSTANT(RESULT_NO_MATCHING_URL);
	BIND_ENUM_CONSTANT(RESULT_BAD_RESPONSE);
	BIND_ENUM_CONSTANT(RESULT_REQUIRE_PASSWORD_REENTRY);
	BIND_ENUM_CONSTANT(RESULT_VALUE_OUT_OF_RANGE);
	BIND_ENUM_CONSTANT(RESULT_UNEXPECTED_ERROR);
	BIND_ENUM_CONSTANT(RESULT_DISABLED);
	BIND_ENUM_CONSTANT(RESULT_INVALID_CEG_SUBMISSION);
	BIND_ENUM_CONSTANT(RESULT_RESTRICTED_DEVICE);
	BIND_ENUM_CONSTANT(RESULT_REGION_LOCKED);
	BIND_ENUM_CONSTANT(RESULT_RATE_LIMIT_EXCEEDED);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_LOGIN_DENIED_NEED_TWO_FACTOR);
	BIND_ENUM_CONSTANT(RESULT_ITEM_DELETED);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_LOGIN_DENIED_THROTTLE);
	BIND_ENUM_CONSTANT(RESULT_TWO_FACTOR_CODE_MISMATCH);
	BIND_ENUM_CONSTANT(RESULT_TWO_FACTOR_ACTIVATION_CODE_MISMATCH);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_ASSOCIATED_TO_MULTIPLE_PARTNERS);
	BIND_ENUM_CONSTANT(RESULT_NOT_MODIFIED);
	BIND_ENUM_CONSTANT(RESULT_NO_MOBILE_DEVICE);
	BIND_ENUM_CONSTANT(RESULT_TIME_NOT_SYNCED);
	BIND_ENUM_CONSTANT(RESULT_SMS_CODE_FAILED);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_LIMIT_EXCEEDED);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_ACTIVITY_LIMIT_EXCEEDED);
	BIND_ENUM_CONSTANT(RESULT_PHONE_ACTIVITY_LIMIT_EXCEEDED);
	BIND_ENUM_CONSTANT(RESULT_REFUND_TO_WALLET);
	BIND_ENUM_CONSTANT(RESULT_EMAIL_SEND_FAILURE);
	BIND_ENUM_CONSTANT(RESULT_NOT_SETTLED);
	BIND_ENUM_CONSTANT(RESULT_NEED_CAPTCHA);
	BIND_ENUM_CONSTANT(RESULT_GSLT_DENIED);
	BIND_ENUM_CONSTANT(RESULT_GS_OWNER_DENIED);
	BIND_ENUM_CONSTANT(RESULT_INVALID_ITEM_TYPE);
	BIND_ENUM_CONSTANT(RESULT_IP_BANNED);
	BIND_ENUM_CONSTANT(RESULT_GSLT_EXPIRED);
	BIND_ENUM_CONSTANT(RESULT_INSUFFICIENT_FUNDS);
	BIND_ENUM_CONSTANT(RESULT_TOO_MANY_PENDING);
	BIND_ENUM_CONSTANT(RESULT_NO_SITE_LICENSES_FOUND);
	BIND_ENUM_CONSTANT(RESULT_WG_NETWORK_SEND_EXCEEDED);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_NOT_FRIENDS);
	BIND_ENUM_CONSTANT(RESULT_LIMITED_USER_ACCOUNT);
	BIND_ENUM_CONSTANT(RESULT_CANT_REMOVE_ITEM);
	BIND_ENUM_CONSTANT(RESULT_ACCOUNT_DELETED);
	BIND_ENUM_CONSTANT(RESULT_EXISTING_USER_CANCELLED_LICENSE);
	BIND_ENUM_CONSTANT(RESULT_COMMUNITY_COOLDOWN);
	BIND_ENUM_CONSTANT(RESULT_NO_LAUNCHER_SPECIFIED);
	BIND_ENUM_CONSTANT(RESULT_MUST_AGREE_TO_SSA);
	BIND_ENUM_CONSTANT(RESULT_LAUNCHER_MIGRATED);
	BIND_ENUM_CONSTANT(RESULT_STEAM_REALM_MISMATCH);
	BIND_ENUM_CONSTANT(RESULT_INVALID_SIGNATURE);
	BIND_ENUM_CONSTANT(RESULT_PARSE_FAILURE);
	BIND_ENUM_CONSTANT(RESULT_NO_VERIFIED_PHONE);
	BIND_ENUM_CONSTANT(RESULT_INSUFFICIENT_BATTERY);
	BIND_ENUM_CONSTANT(RESULT_CHARGER_REQUIRED);
	BIND_ENUM_CONSTANT(RESULT_CACHED_CREDENTIAL_INVALID);
	BIND_ENUM_CONSTANT(RESULT_PHONE_NUMBER_IS_VOIP);

	// ServerMode Enums
	BIND_ENUM_CONSTANT(SERVER_MODE_INVALID);
	BIND_ENUM_CONSTANT(SERVER_MODE_NO_AUTHENTICATION);
	BIND_ENUM_CONSTANT(SERVER_MODE_AUTHENTICATION);
	BIND_ENUM_CONSTANT(SERVER_MODE_AUTHENTICATION_AND_SECURE);

	// SocketConnectionType Enums
	BIND_ENUM_CONSTANT(NET_SOCKET_CONNECTION_TYPE_NOT_CONNECTED);
	BIND_ENUM_CONSTANT(NET_SOCKET_CONNECTION_TYPE_UDP);
	BIND_ENUM_CONSTANT(NET_SOCKET_CONNECTION_TYPE_UDP_RELAY);

	// SocketState Enums
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_INVALID);
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_CONNECTED);
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_INITIATED);
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_LOCAL_CANDIDATE_FOUND);
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_RECEIVED_REMOTE_CANDIDATES);
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_CHALLENGE_HANDSHAKE);
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_DISCONNECTING);
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_LOCAL_DISCONNECT);
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_TIMEOUT_DURING_CONNECT);
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_REMOTE_END_DISCONNECTED);
	BIND_ENUM_CONSTANT(NET_SOCKET_STATE_BROKEN);

	// SteamAPIInitResult Enums
	BIND_ENUM_CONSTANT(STEAM_API_INIT_RESULT_OK);
	BIND_ENUM_CONSTANT(STEAM_API_INIT_RESULT_FAILED_GENERIC);
	BIND_ENUM_CONSTANT(STEAM_API_INIT_RESULT_NO_STEAM_CLIENT);
	BIND_ENUM_CONSTANT(STEAM_API_INIT_RESULT_VERSION_MISMATCH);

	// UGCContentDescriptorID Enums
	BIND_ENUM_CONSTANT(UGCCONTENTDESCRIPTOR_NUDITY_OR_SEXUAL_CONTENT);
	BIND_ENUM_CONSTANT(UGCCONTENTDESCRIPTOR_FREQUENT_VIOLENCE_OR_GORE);
	BIND_ENUM_CONSTANT(UGCCONTENTDESCRIPTOR_ADULT_ONLY_SEXUAL_CONTENT);
	BIND_ENUM_CONSTANT(UGCCONTENTDESCRIPTOR_GRATUITOUS_SEXUAL_CONTENT);
	BIND_ENUM_CONSTANT(UGCCONTENTDESCRIPTOR_ANY_MATURE_CONTENT);

	// UGCMatchingUGCType Enums
	BIND_ENUM_CONSTANT(UGC_MATCHINGUGCTYPE_ITEMS);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_ITEMS_MTX);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_ITEMS_READY_TO_USE);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_COLLECTIONS);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_ARTWORK);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_VIDEOS);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_SCREENSHOTS);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_ALL_GUIDES);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_WEB_GUIDES);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_INTEGRATED_GUIDES);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_USABLE_IN_GAME);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_CONTROLLER_BINDINGS);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_GAME_MANAGED_ITEMS);
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_ALL);

	// UGCQuery Enums
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_VOTE);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_PUBLICATION_DATE);
	BIND_ENUM_CONSTANT(UGC_QUERY_ACCEPTED_FOR_GAME_RANKED_BY_ACCEPTANCE_DATE);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_TREND);
	BIND_ENUM_CONSTANT(UGC_QUERY_FAVORITED_BY_FRIENDS_RANKED_BY_PUBLICATION_DATE);
	BIND_ENUM_CONSTANT(UGC_QUERY_CREATED_BY_FRIENDS_RANKED_BY_PUBLICATION_DATE);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_NUM_TIMES_REPORTED);
	BIND_ENUM_CONSTANT(UGC_QUERY_CREATED_BY_FOLLOWED_USERS_RANKED_BY_PUBLICATION_DATE);
	BIND_ENUM_CONSTANT(UGC_QUERY_NOT_YET_RATED);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_TOTAL_VOTES_ASC);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_VOTES_UP);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_TEXT_SEARCH);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_TOTAL_UNIQUE_SUBSCRIPTIONS);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_PLAYTIME_TREND);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_TOTAL_PLAYTIME);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_AVERAGE_PLAYTIME_TREND);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_LIFETIME_AVERAGE_PLAYTIME);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_PLAYTIME_SESSIONS_TREND);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_LIFETIME_PLAYTIME_SESSIONS);
	BIND_ENUM_CONSTANT(UGC_QUERY_RANKED_BY_LAST_UPDATED_DATE);

	// UGCReadAction Enums
	BIND_ENUM_CONSTANT(UGC_READ_CONTINUE_READING_UNTIL_FINISHED);
	BIND_ENUM_CONSTANT(UGC_READ_CONTINUE_READING);
	BIND_ENUM_CONSTANT(UGC_READ_CLOSE);

	// Universe Enums
	BIND_ENUM_CONSTANT(UNIVERSE_INVALID);
	BIND_ENUM_CONSTANT(UNIVERSE_PUBLIC);
	BIND_ENUM_CONSTANT(UNIVERSE_BETA);
	BIND_ENUM_CONSTANT(UNIVERSE_INTERNAL);
	BIND_ENUM_CONSTANT(UNIVERSE_DEV);
	BIND_ENUM_CONSTANT(UNIVERSE_MAX);

	// UserRestriction Enums
	BIND_BITFIELD_FLAG(USER_RESTRICTION_NONE);
	BIND_BITFIELD_FLAG(USER_RESTRICTION_UNKNOWN);
	BIND_BITFIELD_FLAG(USER_RESTRICTION_ANY_CHAT);
	BIND_BITFIELD_FLAG(USER_RESTRICTION_VOICE_CHAT);
	BIND_BITFIELD_FLAG(USER_RESTRICTION_GROUP_CHAT);
	BIND_BITFIELD_FLAG(USER_RESTRICTION_RATING);
	BIND_BITFIELD_FLAG(USER_RESTRICTION_GAME_INVITES);
	BIND_BITFIELD_FLAG(USER_RESTRICTION_TRADING);

	// UserUGCList Enums
	BIND_ENUM_CONSTANT(USER_UGC_LIST_PUBLISHED);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_VOTED_ON);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_VOTED_UP);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_VOTED_DOWN);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_WILL_VOTE_LATER);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_FAVORITED);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_SUBSCRIBED);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_USED_OR_PLAYED);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_FOLLOWED);

	// UserUGCListSortOrder Enums
	BIND_ENUM_CONSTANT(USERUGCLISTSORTORDER_CREATIONORDERDESC);
	BIND_ENUM_CONSTANT(USERUGCLISTSORTORDER_CREATIONORDERASC);
	BIND_ENUM_CONSTANT(USERUGCLISTSORTORDER_TITLEASC);
	BIND_ENUM_CONSTANT(USERUGCLISTSORTORDER_LASTUPDATEDDESC);
	BIND_ENUM_CONSTANT(USERUGCLISTSORTORDER_SUBSCRIPTIONDATEDESC);
	BIND_ENUM_CONSTANT(USERUGCLISTSORTORDER_VOTESCOREDESC); 
	BIND_ENUM_CONSTANT(SERUGCLISTSORTORDER_FORMODERATION);

	// WorkshopEnumerationType Enums
	BIND_ENUM_CONSTANT(WORKSHOP_ENUMERATION_TYPE_RANKED_BY_VOTE);
	BIND_ENUM_CONSTANT(WORKSHOP_ENUMERATION_TYPE_RECENT);
	BIND_ENUM_CONSTANT(WORKSHOP_ENUMERATION_TYPE_TRENDING);
	BIND_ENUM_CONSTANT(WORKSHOP_ENUMERATION_TYPE_FAVORITES_OF_FRIENDS);
	BIND_ENUM_CONSTANT(WORKSHOP_ENUMERATION_TYPE_VOTED_BY_FRIENDS);
	BIND_ENUM_CONSTANT(WORKSHOP_ENUMERATION_TYPE_CONTENT_BY_FRIENDS);
	BIND_ENUM_CONSTANT(WORKSHOP_ENUMERATION_TYPE_RECENT_FROM_FOLLOWED_USERS);

	// WorkshopFileAction Enums
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_ACTION_PLAYED);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_ACTION_COMPLETED);

	// WorkshopFileType Enums
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_FIRST);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_COMMUNITY);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_MICROTRANSACTION);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_COLLECTION);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_ART);
	BIND_ENUM_CONSTANT(wORKSHOP_FILE_TYPE_VIDEO);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_SCREENSHOT);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_GAME);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_SOFTWARE);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_CONCEPT);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_WEB_GUIDE);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_INTEGRATED_GUIDE);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_MERCH);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_CONTROLLER_BINDING);
	BIND_ENUM_CONSTANT(wORKSHOP_FILE_TYPE_STEAMWORKS_ACCESS_INVITE);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_STEAM_VIDEO);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_GAME_MANAGED_ITEM);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_MAX);

	// WorkshopVideoProvider Enums
	BIND_ENUM_CONSTANT(WORKSHOP_VIDEO_PROVIDER_NONE);
	BIND_ENUM_CONSTANT(WORKSHOP_VIDEO_PROVIDER_YOUTUBE);

	// WorkshopVote Enums
	BIND_ENUM_CONSTANT(WORKSHOP_VOTE_UNVOTED);
	BIND_ENUM_CONSTANT(WORKSHOP_VOTE_FOR);
	BIND_ENUM_CONSTANT(WORKSHOP_VOTE_AGAINST);
	BIND_ENUM_CONSTANT(WORKSHOP_VOTE_LATER);

}

SteamServer::~SteamServer(){
	if(is_init_success){
		SteamGameServer_Shutdown();
	}

	// Clear app ID, and singleton variables ////
	singleton = nullptr;
}
