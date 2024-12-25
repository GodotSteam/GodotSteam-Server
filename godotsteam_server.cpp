// Turn off MSVC-only warning about strcpy
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#pragma warning(disable:4996)
#pragma warning(disable:4828)
#endif


// Include GodotSteam Server header
#include "godotsteam_server.h"

// Include some system headers
#include "fstream"
#include "vector"


SteamServer *SteamServer::singleton = NULL;


SteamServer::SteamServer():
	// Game Server
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

	// Game Server Stats
	callbackStatsStored(this, &SteamServer::stats_stored),
	callbackStatsUnloaded(this, &SteamServer::stats_unloaded),

	// HTTP
	callbackHTTPRequestCompleted(this, &SteamServer::http_request_completed),
	callbackHTTPRequestDataReceived(this, &SteamServer::http_request_data_received),
	callbackHTTPRequestHeadersReceived(this, &SteamServer::http_request_headers_received),

	// Inventory
	callbackInventoryDefinitionUpdate(this, &SteamServer::inventory_definition_update),
	callbackInventoryFullUpdate(this, &SteamServer::inventory_full_update),
	callbackInventoryResultReady(this, &SteamServer::inventory_result_ready),

	// Networking
	callbackP2PSessionConnectFail(this, &SteamServer::p2p_session_connect_fail),
	callbackP2PSessionRequest(this, &SteamServer::p2p_session_request),

	// Networking Messages
	callbackNetworkMessagesSessionRequest(this, &SteamServer::network_messages_session_request),
	callbackNetworkMessagesSessionFailed(this, &SteamServer::network_messages_session_failed),

	// Networking Sockets
	callbackNetworkConnectionStatusChanged(this, &SteamServer::network_connection_status_changed),
	callbackNetworkAuthenticationStatus(this, &SteamServer::network_authentication_status),
	callbackNetworkingFakeIPResult(this, &SteamServer::fake_ip_result),

	// Networking Utils
	callbackRelayNetworkStatus(this, &SteamServer::relay_network_status),

	// Remote Storage
	callbackLocalFileChanged(this, &SteamServer::local_file_changed),

	// UGC
	callbackItemDownloaded(this, &SteamServer::item_downloaded),
	callbackItemInstalled(this, &SteamServer::item_installed),
	callbackUserSubscribedItemsListChanged(this, &SteamServer::user_subscribed_items_list_changed)
{
	is_init_success = false;
	singleton = this;
}


///// INTERNAL

// Helper function to turn an array of options into an array of SteamNetworkingConfigValue_t structs
// These arrays contain dictionaries of { NetworkingConfigValue enum : value for config }
const SteamNetworkingConfigValue_t *SteamServer::convert_config_options(Dictionary config_options) {
	uint32 options_size = config_options.size();
	SteamNetworkingConfigValue_t *option_array = new SteamNetworkingConfigValue_t[options_size];

	if (options_size > 0) {
		for (uint32 i = 0; i < options_size; i++) {
			SteamNetworkingConfigValue_t this_option;
			int sent_option = (int)config_options.keys()[i];

			// Get the configuration value.
			// This is a convoluted way of doing it but can't seem to cast the value as an enum so here we are.
			ESteamNetworkingConfigValue this_value = ESteamNetworkingConfigValue((int)sent_option);
			Variant::Type value_type = config_options[sent_option].get_type();
			if (value_type == Variant::INT) {
				if (sent_option == NETWORKING_CONFIG_CONNECTION_USER_DATA) {
					this_option.SetInt64(this_value, config_options[sent_option]);
				} 
				else {
					this_option.SetInt32(this_value, config_options[sent_option]);
				}
			}
			else if (value_type == Variant::REAL) {
				this_option.SetFloat(this_value, config_options[sent_option]);
			}
			else if (value_type == Variant::STRING) {
				this_option.SetString(this_value, String(config_options[sent_option]).utf8().get_data());
			}
			else {
				Object *this_pointer;
				this_pointer = config_options[sent_option];
				this_option.SetPtr(this_value, this_pointer);
			}
			option_array[i] = this_option;
		}
	}
	return option_array;
}

// Creating a Steam ID for internal use
CSteamID SteamServer::createSteamID(uint64_t steam_id, AccountType account_type) {
	CSteamID converted_steam_id;
	if (account_type < 0 || account_type >= AccountType(k_EAccountTypeMax)) {
		account_type = ACCOUNT_TYPE_INDIVIDUAL;
	}
	converted_steam_id.Set(steam_id, k_EUniversePublic, EAccountType(account_type));
	return converted_steam_id;
}

// Get the Steam singleton, obviously
SteamServer* SteamServer::get_singleton() {
	return singleton;
}

// Convert a Steam ID to a Steam Identity
SteamNetworkingIdentity SteamServer::getIdentityFromSteamID(uint64_t steam_id) {
	SteamNetworkingIdentity remote_identity;
	remote_identity.SetSteamID64(steam_id);
	return remote_identity;
}

// Convert a string IP address to an integer
uint32 SteamServer::getIPFromString(String ip_string) {
	uint32 ip_address = 0;

	SteamNetworkingIPAddr this_address;
	this_address.Clear();
	
	if (this_address.ParseString(ip_string.utf8().get_data())) {
		ip_address = this_address.GetIPv4();
	}
	return ip_address;
}

// Convert a Steam IP Address object to an integer
uint32 SteamServer::getIPFromSteamIP(SteamNetworkingIPAddr this_address) {
	return this_address.GetIPv4();
}

// Get the Steam ID from an identity struct
uint64_t SteamServer::getSteamIDFromIdentity(SteamNetworkingIdentity this_identity) {
	uint64_t this_steam_id = this_identity.GetSteamID64();
	return this_steam_id;
}

// Convert an integer to a Steam IP Address
SteamNetworkingIPAddr SteamServer::getSteamIPFromInt(uint32 ip_integer) {
	SteamNetworkingIPAddr this_address;
	this_address.Clear();

	if (ip_integer > 0) {
		this_address.SetIPv4(ip_integer, 0);
	}
	return this_address;
}

// Convert an IP string to a Steam IP Address
SteamNetworkingIPAddr SteamServer::getSteamIPFromString(String ip_string) {
	SteamNetworkingIPAddr this_address;
	this_address.Clear();
	
	if (this_address.ParseString(ip_string.utf8().get_data())) {
		this_address.GetIPv4();
	}
	return this_address;
}

// Convert an integer IP address to a string
String SteamServer::getStringFromIP(uint32 ip_integer) {
	String ip_address = "";

	SteamNetworkingIPAddr this_address;
	this_address.Clear();

	if (ip_integer > 0) {
		this_address.SetIPv4(ip_integer, 0);
		char this_ip[16];
		this_address.ToString(this_ip, 16, false);
		ip_address = String(this_ip);
	}
	return ip_address;
}

// Convert a Steam IP Address to a string
String SteamServer::getStringFromSteamIP(SteamNetworkingIPAddr this_address) {
	char this_ip[16];
	this_address.ToString(this_ip, 16, false);
	return String(this_ip);
}


///// MAIN FUNCTIONS

// Convert a SteamID64 into a SteamID
uint32_t SteamServer::getSteamID32(uint64_t steam_id) {
	CSteamID this_steam_id = (uint64)steam_id;
	return this_steam_id.GetAccountID();
}

// Gets the server's Steam ID.
uint64_t SteamServer::getServerSteamID() {
	return SteamGameServer_GetSteamID();
}

// Is this an anonymous account?
bool SteamServer::isAnonAccount(uint64_t steam_id) {
	CSteamID this_steam_id = (uint64)steam_id;
	return this_steam_id.BAnonAccount();
}

// Is this an anonymous user account? Used to create an account or reset a password, but do not try to do this.
bool SteamServer::isAnonUserAccount(uint64_t steam_id) {
	CSteamID this_steam_id = (uint64)steam_id;
	return this_steam_id.BAnonUserAccount();
}

// Is this a chat account ID?
bool SteamServer::isChatAccount(uint64_t steam_id) {
	CSteamID this_steam_id = (uint64)steam_id;
	return this_steam_id.BChatAccount();
}

// Is this a clan account ID?
bool SteamServer::isClanAccount(uint64_t steam_id) {
	CSteamID this_steam_id = (uint64)steam_id;
	return this_steam_id.BClanAccount();
}

// Is this a faked up Steam ID for a PSN friend account?
bool SteamServer::isConsoleUserAccount(uint64_t steam_id) {
	CSteamID this_steam_id = (uint64)steam_id;
	return this_steam_id.BConsoleUserAccount();
}

// Is this an individual user account ID?
bool SteamServer::isIndividualAccount(uint64_t steam_id) {
	CSteamID this_steam_id = (uint64)steam_id;
	return this_steam_id.BIndividualAccount();
}

// Is this a lobby account ID?
bool SteamServer::isLobby(uint64_t steam_id) {
	CSteamID this_steam_id = (uint64)steam_id;
	return this_steam_id.IsLobby();
}

// No official notes, but should be checking if the server is secured.
bool SteamServer::isServerSecure() {
	return SteamGameServer_BSecure();
}

// Initialize SteamGameServer client and interface objects, and set server properties which may not be changed.
// After calling this function, you should set any additional server parameters, and then logOnAnonymous() or logOn().
bool SteamServer::serverInit(const String &ip, uint16 game_port, uint16 query_port, ServerMode server_mode, const String &version_number) {
	if (!SteamGameServer_Init(getIPFromString(ip), game_port, query_port, (EServerMode)server_mode, version_number.utf8().get_data())) {
		return false;
	}
	return true;
}

// Initialize SteamGameServer client and interface objects, and set server properties which may not be changed.
// After calling this function, you should set any additional server parameters, and then logOnAnonymous() or logOn().
// On success STEAM_API_INIT_RESULT_OK is returned.  Otherwise, if error_message is non-NULL, it will receive a non-localized message that explains the reason for the failure
Dictionary SteamServer::serverInitEx(const String &ip, uint16 game_port, uint16 query_port, ServerMode server_mode, const String &version_number) {
	char error_message[STEAM_MAX_ERROR_MESSAGE] = "Server initialized successfully";
	ESteamAPIInitResult initialize_result = k_ESteamAPIInitResult_FailedGeneric;
	initialize_result = SteamGameServer_InitEx(getIPFromString(ip), game_port, query_port, (EServerMode)server_mode, version_number.utf8().get_data(), &error_message);

	Dictionary server_initialize;
	server_initialize["status"] = initialize_result;
	server_initialize["verbal"] = error_message;

	return server_initialize;
}

// Frees all API-related memory associated with the calling thread. This memory is released automatically by RunCallbacks so single-threaded servers do not need to call this.
void SteamServer::serverReleaseCurrentThreadMemory() {
	SteamAPI_ReleaseCurrentThreadMemory();
}

// Shut down the server connection to Steam.
void SteamServer::serverShutdown() {
	SteamGameServer_Shutdown();
}


///// GAME SERVER FUNCTIONS

// NOTE: The following, if set, must be set before calling LogOn; they may not be changed after.
//
// Game product identifier; currently used by the master server for version checking purposes.
void SteamServer::setProduct(const String &product) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setProduct");
	SteamGameServer()->SetProduct(product.utf8().get_data());
}

// Description of the game; required field and is displayed in the Steam server browser.
void SteamServer::setGameDescription(const String &description) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setGameDescription");
	SteamGameServer()->SetGameDescription(description.utf8().get_data());
}

// If your game is a mod, pass the string that identifies it. Default is empty meaning the app is the original game.
void SteamServer::setModDir(const String &mod_directory) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setModDir");
	SteamGameServer()->SetModDir(mod_directory.utf8().get_data());
}

// Is this a dedicated server? Default is false.
void SteamServer::setDedicatedServer(bool dedicated) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setDedicatedServer");
	SteamGameServer()->SetDedicatedServer(dedicated);
}

// NOTE: The following are login functions.
//
// Begin process to login to a persistent game server account. You need to register for callbacks to determine the result of this operation.
void SteamServer::logOn(const String &token) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: logOn");
	SteamGameServer()->LogOn(token.utf8().get_data());
}

// Login to a generic, anonymous account.
void SteamServer::logOnAnonymous() {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: logOnAnonymous");
	SteamGameServer()->LogOnAnonymous();
}

// Begin process of logging game server out of Steam.
void SteamServer::logOff() {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: logOff");
	SteamGameServer()->LogOff();
}

// Status functions.
bool SteamServer::loggedOn() {
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, false, "[STEAM SERVER] Server class not found when calling: loggedOn");
	return SteamGameServer()->BLoggedOn();
}

bool SteamServer::secure() {
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, false, "[STEAM SERVER] Server class not found when calling: secure");
	return SteamGameServer()->BSecure();
}

uint64_t SteamServer::getSteamID() {
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, 0, "[STEAM SERVER] Server class not found when calling: getSteamID");
	CSteamID serverID = SteamGameServer()->GetSteamID();
	return serverID.ConvertToUint64();
}

// Returns true if the master server has requested a restart. Only returns true once per request.
bool SteamServer::wasRestartRequested() {
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, false, "[STEAM SERVER] Server class not found when calling: wasRestartRequested");
	return SteamGameServer()->WasRestartRequested();
}

// NOTE: These are server state functions and can be changed at any time.
//
// Max player count that will be reported to server browser and client queries.
void SteamServer::setMaxPlayerCount(int players_max) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setMaxPlayerCount");
	SteamGameServer()->SetMaxPlayerCount(players_max);
}

// Number of bots. Default is zero.
void SteamServer::setBotPlayerCount(int bots) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setBotPlayerCount");
	SteamGameServer()->SetBotPlayerCount(bots);
}

// Set the naem of the server as it will appear in the server browser.
void SteamServer::setServerName(const String &name) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setServerName");
	SteamGameServer()->SetServerName(name.utf8().get_data());
}

// Set name of map to report in server browser.
void SteamServer::setMapName(const String &map) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setMapName");
	SteamGameServer()->SetMapName(map.utf8().get_data());
}

// Let people know if your server requires a password.
void SteamServer::setPasswordProtected(bool password_protected) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setPasswordProtected");
	SteamGameServer()->SetPasswordProtected(password_protected);
}

// Spectator server. Default is zero, meaning it is now used.
void SteamServer::setSpectatorPort(uint16 port) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setSpectatorPort");
	SteamGameServer()->SetSpectatorPort(port);
}

// Name of spectator server. Only used if spectator port is non-zero.
void SteamServer::setSpectatorServerName(const String &name) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setSpectatorServerName");
	SteamGameServer()->SetSpectatorServerName(name.utf8().get_data());
}

// Call this to clear the whole list of key/values that are sent in rule queries.
void SteamServer::clearAllKeyValues() {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: clearAllKeyValues");
	SteamGameServer()->ClearAllKeyValues();
}

// Call this to add/update a key/value pair.
void SteamServer::setKeyValue(const String &key, const String &value) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setKeyValue");
	SteamGameServer()->SetKeyValue(key.utf8().get_data(), value.utf8().get_data());
}

// Set a string defining game tags for this server; optional. Allows users to filter in matchmaking/server browser.
void SteamServer::setGameTags(const String &tags) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setGameTags");
	SteamGameServer()->SetGameTags(tags.utf8().get_data());
}

// Set a string defining game data for this server; optional. Allows users to filter in matchmaking/server browser.
void SteamServer::setGameData(const String &data) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setGameData");
	SteamGameServer()->SetGameData(data.utf8().get_data());
}

// Region identifier; optional. Default is empty meaning 'world'.
void SteamServer::setRegion(const String &region) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setRegion");
	SteamGameServer()->SetRegion(region.utf8().get_data());
}

// NOTE: These functions are player list management / authentication.
//
// Retrieve ticket to be sent to the entity who wishes to authenticate you (using BeginAuthSession API).
Dictionary SteamServer::getAuthSessionTicket(uint64_t remote_steam_id) {
	Dictionary auth_ticket;
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, auth_ticket, "[STEAM SERVER] Server class not found when calling: getAuthSessionTicket");
	uint32_t id = 0;
	uint32_t ticket_size = 1024;
	PoolByteArray buffer;
	buffer.resize(ticket_size);
	
	if (remote_steam_id == 0) {
		SteamNetworkingIdentity auth_identity = getIdentityFromSteamID(remote_steam_id);
		id = SteamGameServer()->GetAuthSessionTicket(buffer.write().ptr(), ticket_size, &ticket_size, &auth_identity);
	}
	else{
		id = SteamGameServer()->GetAuthSessionTicket(buffer.write().ptr(), ticket_size, &ticket_size, NULL);
	}
	// Add this data to the dictionary
	auth_ticket["id"] = id;
	auth_ticket["buffer"] = buffer;
	auth_ticket["size"] = ticket_size;
	return auth_ticket;
}

// Authenticate the ticket from the entity Steam ID to be sure it is valid and isn't reused.
uint32 SteamServer::beginAuthSession(PoolByteArray ticket, int ticket_size, uint64_t steam_id) {
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, -1, "[STEAM SERVER] Server class not found when calling: beginAuthSession");
	CSteamID auth_steam_id = createSteamID(steam_id);
	return SteamGameServer()->BeginAuthSession(ticket.read().ptr(), ticket_size, auth_steam_id);
}

// Stop tracking started by beginAuthSession; called when no longer playing game with this entity;
void SteamServer::endAuthSession(uint64_t steam_id) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: endAuthSession");
	CSteamID auth_steam_id = createSteamID(steam_id);
	SteamGameServer()->EndAuthSession(auth_steam_id);
}

// Cancel auth ticket from getAuthSessionTicket; called when no longer playing game with the entity you gave the ticket to.
void SteamServer::cancelAuthTicket(uint32_t auth_ticket) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: cancelAuthTicket");
	SteamGameServer()->CancelAuthTicket(auth_ticket);
}

// After receiving a user's authentication data, and passing it to sendUserConnectAndAuthenticate, use to determine if user owns DLC
int SteamServer::userHasLicenceForApp(uint64_t steam_id, uint32 app_id) {
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, 0, "[STEAM SERVER] Server class not found when calling: userHasLicenceForApp");
	CSteamID user_id = (uint64)steam_id;
	return SteamGameServer()->UserHasLicenseForApp(user_id, (AppId_t)app_id);
}

// Ask if user is in specified group; results returned by GSUserGroupStatus_t.
bool SteamServer::requestUserGroupStatus(uint64_t steam_id, int group_id) {
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, false, "[STEAM SERVER] Server class not found when calling: requestUserGroupStatus");
	CSteamID user_id = (uint64)steam_id;
	CSteamID clan_id = (uint64)group_id;
	return SteamGameServer()->RequestUserGroupStatus(user_id, clan_id);
}

// NOTE: These are in GameSocketShare mode, where instead of ISteamGameServer creating sockets to talk to master server, it lets the game use its socket to forward messages back and forth.
//
// These are used when you've elected to multiplex the game server's UDP socket rather than having the master server updater use its own sockets.
Dictionary SteamServer::handleIncomingPacket(int packet, const String &ip, uint16 port) {
	Dictionary result;
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, result, "[STEAM SERVER] Server class not found when calling: handleIncomingPacket");
	PoolByteArray data;
	data.resize(packet);
	if (SteamGameServer()->HandleIncomingPacket(data.write().ptr(), packet, getIPFromString(ip), port)) {
		result["data"] = data;
	}
	return result;
}

// AFTER calling HandleIncomingPacket for any packets that came in that frame, call this. This gets a packet that the master server updater needs to send out on UDP. Returns 0 if there are no more packets.
Dictionary SteamServer::getNextOutgoingPacket() {
	Dictionary packet;
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, packet, "[STEAM SERVER] Server class not found when calling: getNextOutgoingPacket");
	PoolByteArray out;
	int max_out = 16 * 1024;
	uint32 address;
	uint16 port;
	// Retrieve the packet information
	int length = SteamGameServer()->GetNextOutgoingPacket(&out, max_out, &address, &port);
	// Place packet information in dictionary and return it
	packet["length"] = length;
	packet["out"] = out;
	packet["address"] = address;
	packet["port"] = port;
	return packet;
}

// Gets the public IP of the server according to Steam.
Dictionary SteamServer::getPublicIP() {
	Dictionary public_ip;
	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, public_ip, "[STEAM SERVER] Server class not found when calling: getPublicIP");
	SteamIPAddress_t this_public_ip = SteamGameServer()->GetPublicIP();

	uint8 *ipv6_address = new uint8[16];
	ipv6_address = this_public_ip.m_rgubIPv6;

	public_ip["ipv4"] = this_public_ip.m_unIPv4;
	public_ip["ipv6"] = ipv6_address;
	public_ip["type"] = this_public_ip.m_eType;
	return public_ip;
}

// NOTE: These are heartbeat/advertisement functions.
//
// Call this as often as you like to tell the master server updater whether or not you want it to be active (default: off).
void SteamServer::setAdvertiseServerActive(bool active) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: setAdvertiseServerActive");
	SteamGameServer()->SetAdvertiseServerActive(active);
}

// Associate this game server with this clan for the purposes of computing player compatibility.
void SteamServer::associateWithClan(uint64_t clan_id) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: associateWithClan");
	CSteamID group_id = (uint64)clan_id;
	SteamGameServer()->AssociateWithClan(group_id);
}

// Ask if any of the current players dont want to play with this new player - or vice versa.
void SteamServer::computeNewPlayerCompatibility(uint64_t steam_id) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server class not found when calling: computeNewPlayerCompatibility");
	CSteamID user_id = (uint64)steam_id;
	SteamGameServer()->ComputeNewPlayerCompatibility(user_id);
}


///// GAME SERVER STATS

// Resets the unlock status of an achievement for the specified user.
bool SteamServer::clearUserAchievement(uint64_t steam_id, const String &name) {
	ERR_FAIL_COND_V_MSG(SteamGameServerStats() == NULL, false, "[STEAM SERVER] Server Stats class not found when calling: clearUserAchievement");
	CSteamID user_id = (uint64)steam_id;
	return SteamGameServerStats()->ClearUserAchievement(user_id, name.utf8().get_data());
}

// Gets the unlock status of the Achievement.
Dictionary SteamServer::getUserAchievement(uint64_t steam_id, const String &name) {
	Dictionary achieve;
	ERR_FAIL_COND_V_MSG(SteamGameServerStats() == NULL, achieve, "[STEAM SERVER] Server Stats class not found when calling: getUserAchievement");
	bool achieved = false;
	CSteamID user_id = (uint64)steam_id;

	bool success = SteamGameServerStats()->GetUserAchievement(user_id, name.utf8().get_data(), &achieved);
	if (success) {
		achieve["steam_id"] = steam_id;
		achieve["retrieved"] = success;
		achieve["name"] = name;
		achieve["achieved"] = achieved;
	}
	return achieve;
}

// Gets the current value of the a stat for the specified user.
float SteamServer::getUserStatFloat(uint64_t steam_id, const String &name) {
	ERR_FAIL_COND_V_MSG(SteamGameServerStats() == NULL, 0, "[STEAM SERVER] Server Stats class not found when calling: getUserStatFloat");
	float stat_value = 0.0;
	CSteamID user_id = (uint64)steam_id;
	SteamGameServerStats()->GetUserStat(user_id, name.utf8().get_data(), &stat_value);
	return stat_value;
}

// Gets the current value of the a stat for the specified user.
uint32_t SteamServer::getUserStatInt(uint64_t steam_id, const String &name) {
	ERR_FAIL_COND_V_MSG(SteamGameServerStats() == NULL, 0, "[STEAM SERVER] Server Stats class not found when calling: getUserStatInt");
	int32_t stat_value = 0;
	CSteamID user_id = (uint64)steam_id;
	SteamGameServerStats()->GetUserStat(user_id, name.utf8().get_data(), &stat_value);
	return stat_value;
}

// Asynchronously downloads stats and achievements for the specified user from the server.
void SteamServer::requestUserStats(uint64_t steam_id) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server Stats class not found when calling: requestUserStats");
	CSteamID user_id = (uint64)steam_id;
	SteamAPICall_t api_call = SteamGameServerStats()->RequestUserStats(user_id);
	callResultStatReceived.Set(api_call, this, &SteamServer::stats_received);
}

// Unlocks an achievement for the specified user.
bool SteamServer::setUserAchievement(uint64_t steam_id, const String &name) {
	ERR_FAIL_COND_V_MSG(SteamGameServerStats() == NULL, false, "[STEAM SERVER] Server Stats class not found when calling: setUserAchievement");
	CSteamID user_id = (uint64)steam_id;
	return SteamGameServerStats()->SetUserAchievement(user_id, name.utf8().get_data());
}

// Sets / updates the value of a given stat for the specified user.
bool SteamServer::setUserStatFloat(uint64_t steam_id, const String &name, float stat) {
	ERR_FAIL_COND_V_MSG(SteamGameServerStats() == NULL, false, "[STEAM SERVER] Server Stats class not found when calling: setUserStatFloat");
	CSteamID user_id = (uint64)steam_id;
	return SteamGameServerStats()->SetUserStat(user_id, name.utf8().get_data(), stat);
}

// Sets / updates the value of a given stat for the specified user.
bool SteamServer::setUserStatInt(uint64_t steam_id, const String &name, int32 stat) {
	ERR_FAIL_COND_V_MSG(SteamGameServerStats() == NULL, false, "[STEAM SERVER] Server Stats class not found when calling: setUserStatInt");
	CSteamID user_id = (uint64)steam_id;
	return SteamGameServerStats()->SetUserStat(user_id, name.utf8().get_data(), stat);
}

// Send the changed stats and achievements data to the server for permanent storage for the specified user.
void SteamServer::storeUserStats(uint64_t steam_id) {
	ERR_FAIL_COND_MSG(SteamGameServer() == NULL, "[STEAM SERVER] Server Stats class not found when calling: storeUserStats");
	CSteamID user_id = (uint64)steam_id;
	SteamGameServerStats()->StoreUserStats(user_id);
}

// Updates an AVGRATE stat with new values for the specified user.
bool SteamServer::updateUserAvgRateStat(uint64_t steam_id, const String &name, float this_session, double session_length) {
	ERR_FAIL_COND_V_MSG(SteamGameServerStats() == NULL, false, "[STEAM SERVER] Server Stats class not found when calling: updateUserAvgRateStat");
	CSteamID user_id = (uint64)steam_id;
	return SteamGameServerStats()->UpdateUserAvgRateStat(user_id, name.utf8().get_data(), this_session, session_length);
}


///// HTTP

// Creates a cookie container to store cookies during the lifetime of the process. This API is just for during process lifetime, after steam restarts no cookies are persisted and you have no way to access the cookie container across repeat executions of your process.
uint32_t SteamServer::createCookieContainer(bool allow_responses_to_modify) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, 0, "[STEAM SERVER] HTTP class not found when calling: createCookieContainer");
	return SteamHTTP()->CreateCookieContainer(allow_responses_to_modify);
}

// Initializes a new HTTP request.
uint32_t SteamServer::createHTTPRequest(HTTPMethod request_method, const String &absolute_url) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, HTTPREQUEST_INVALID_HANDLE, "[STEAM SERVER] HTTP class not found when calling: createCookieContainer");
	return SteamHTTP()->CreateHTTPRequest((EHTTPMethod)request_method, absolute_url.utf8().get_data());
}

// Defers a request which has already been sent by moving it at the back of the queue.
bool SteamServer::deferHTTPRequest(uint32 request_handle) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: deferHTTPRequest");
	return SteamHTTP()->DeferHTTPRequest(request_handle);
}

// Gets progress on downloading the body for the request.
float SteamServer::getHTTPDownloadProgressPct(uint32 request_handle) {
	float percent_one = 0.0;
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, percent_one, "[STEAM SERVER] HTTP class not found when calling: getHTTPDownloadProgressPct");
	SteamHTTP()->GetHTTPDownloadProgressPct(request_handle, &percent_one);
	return percent_one;
}

// Check if the reason the request failed was because we timed it out (rather than some harder failure).
bool SteamServer::getHTTPRequestWasTimedOut(uint32 request_handle) {
	bool was_timed_out = false;
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, was_timed_out, "[STEAM SERVER] HTTP class not found when calling: getHTTPRequestWasTimedOut");
	SteamHTTP()->GetHTTPRequestWasTimedOut(request_handle, &was_timed_out);
	return was_timed_out;
}

// Gets the body data from an HTTP response.
PoolByteArray SteamServer::getHTTPResponseBodyData(uint32 request_handle, uint32 buffer_size) {
	PoolByteArray body_data;
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, body_data, "[STEAM SERVER] HTTP class not found when calling: getHTTPResponseBodyData");
	body_data.resize(buffer_size);
	SteamHTTP()->GetHTTPResponseBodyData(request_handle, body_data.write().ptr(), buffer_size);
	return body_data;
}

// Gets the size of the body data from an HTTP response.
uint32 SteamServer::getHTTPResponseBodySize(uint32 request_handle) {
	uint32 body_size = 0;
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, body_size, "[STEAM SERVER] HTTP class not found when calling: getHTTPResponseBodySize");
	SteamHTTP()->GetHTTPResponseBodySize(request_handle, &body_size);
	return body_size;
}

// Checks if a header is present in an HTTP response and returns its size.
uint32 SteamServer::getHTTPResponseHeaderSize(uint32 request_handle, const String &header_name) {
	uint32 response_header_size = 0;
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, response_header_size, "[STEAM SERVER] HTTP class not found when calling: getHTTPResponseHeaderSize");
	SteamHTTP()->GetHTTPResponseHeaderSize(request_handle, header_name.utf8().get_data(), &response_header_size);
	return response_header_size;
}

// Gets a header value from an HTTP response.
PoolByteArray SteamServer::getHTTPResponseHeaderValue(uint32 request_handle, const String &header_name, uint32 buffer_size) {
	PoolByteArray header_data;
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, header_data, "[STEAM SERVER] HTTP class not found when calling: getHTTPResponseHeaderValue");
	header_data.resize(buffer_size);
	SteamHTTP()->GetHTTPResponseHeaderValue(request_handle, header_name.utf8().get_data(), header_data.write().ptr(), buffer_size);
	return header_data;
}

// Gets the body data from a streaming HTTP response.
// PoolByteArray SteamServer::getHTTPStreamingResponseBodyData(uint32 request_handle, uint32 offset, uint32 buffer_size) {
// 	PoolByteArray body_data;
// 	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, body_data, "[STEAM SERVER] HTTP class not found when calling: getHTTPStreamingResponseBodyData");
// 	body_data.resize(buffer_size);
// 	SteamHTTP()->GetHTTPStreamingResponseBodyData(request_handle, offset, body_data.read().ptr(), buffer_size);
// 	return body_data;
// }

// Prioritizes a request which has already been sent by moving it at the front of the queue.
bool SteamServer::prioritizeHTTPRequest(uint32 request_handle) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: prioritizeHTTPRequest");
	return SteamHTTP()->PrioritizeHTTPRequest(request_handle);
}

// Releases a cookie container, freeing the memory allocated within Steam.
bool SteamServer::releaseCookieContainer(uint32 cookie_handle) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: releaseCookieContainer");
	return SteamHTTP()->ReleaseCookieContainer(cookie_handle);
}

// Releases an HTTP request handle, freeing the memory allocated within Steam.
bool SteamServer::releaseHTTPRequest(uint32 request_handle) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: releaseHTTPRequest");
	return SteamHTTP()->ReleaseHTTPRequest(request_handle);
}

// Sends an HTTP request.
bool SteamServer::sendHTTPRequest(uint32 request_handle) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: sendHTTPRequest");
	SteamAPICall_t call_handle;
	return SteamHTTP()->SendHTTPRequest(request_handle, &call_handle);
}

// Sends an HTTP request and streams the response back in chunks.
bool SteamServer::sendHTTPRequestAndStreamResponse(uint32 request_handle) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: sendHTTPRequestAndStreamResponse");
	SteamAPICall_t call_handle;
	return SteamHTTP()->SendHTTPRequestAndStreamResponse(request_handle, &call_handle);
}

// Adds a cookie to the specified cookie container that will be used with future requests.
bool SteamServer::setHTTPCookie(uint32 cookie_handle, const String &host, const String &url, const String &cookie) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: setHTTPCookie");
	return SteamHTTP()->SetCookie(cookie_handle, host.utf8().get_data(), url.utf8().get_data(), cookie.utf8().get_data());
}

// Set an absolute timeout in milliseconds for the HTTP request. This is the total time timeout which is different than the network activity timeout which is set with SetHTTPRequestNetworkActivityTimeout which can bump everytime we get more data.
bool SteamServer::setHTTPRequestAbsoluteTimeoutMS(uint32 request_handle, uint32 milliseconds) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: setHTTPRequestAbsoluteTimeoutMS");
	return SteamHTTP()->SetHTTPRequestAbsoluteTimeoutMS(request_handle, milliseconds);
}

// Set a context value for the request, which will be returned in the HTTPRequestCompleted_t callback after sending the request. This is just so the caller can easily keep track of which callbacks go with which request data. Must be called before sending the request.
bool SteamServer::setHTTPRequestContextValue(uint32 request_handle, uint64_t context_value) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: setHTTPRequestContextValue");
	return SteamHTTP()->SetHTTPRequestContextValue(request_handle, context_value);
}

// Associates a cookie container to use for an HTTP request.
bool SteamServer::setHTTPRequestCookieContainer(uint32 request_handle, uint32 cookie_handle) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: setHTTPRequestCookieContainer");
	return SteamHTTP()->SetHTTPRequestCookieContainer(request_handle, cookie_handle);
}

// Set a GET or POST parameter value on the HTTP request. Must be called prior to sending the request.
bool SteamServer::setHTTPRequestGetOrPostParameter(uint32 request_handle, const String &name, const String &value) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: setHTTPRequestGetOrPostParameter");
	return SteamHTTP()->SetHTTPRequestGetOrPostParameter(request_handle, name.utf8().get_data(), value.utf8().get_data());
}

// Set a request header value for the HTTP request. Must be called before sending the request.
bool SteamServer::setHTTPRequestHeaderValue(uint32 request_handle, const String &header_name, const String &header_value) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: setHTTPRequestHeaderValue");
	return SteamHTTP()->SetHTTPRequestHeaderValue(request_handle, header_name.utf8().get_data(), header_value.utf8().get_data());
}

// Set the timeout in seconds for the HTTP request.
bool SteamServer::setHTTPRequestNetworkActivityTimeout(uint32 request_handle, uint32 timeout_seconds) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: setHTTPRequestNetworkActivityTimeout");
	return SteamHTTP()->SetHTTPRequestNetworkActivityTimeout(request_handle, timeout_seconds);
}

// Sets the body for an HTTP Post request.
bool SteamServer::setHTTPRequestRawPostBody(uint32 request_handle, const String &content_type, const String &body) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: setHTTPRequestRawPostBody");
	// Eh, couldn't fix this in time...
//	return SteamHTTP()->SetHTTPRequestRawPostBody(request_handle, content_type.utf8().get_data(), reinterpret_cast<uint8 *>(body.ptr()), body.size());
	return false;
}

// Sets that the HTTPS request should require verified SSL certificate via machines certificate trust store. This currently only works Windows and macOS.
bool SteamServer::setHTTPRequestRequiresVerifiedCertificate(uint32 request_handle, bool require_verified_certificate) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: setHTTPRequestNetworkActivityTimeout");
	return SteamHTTP()->SetHTTPRequestRequiresVerifiedCertificate(request_handle, require_verified_certificate);
}

// Set additional user agent info for a request.
bool SteamServer::setHTTPRequestUserAgentInfo(uint32 request_handle, const String &user_agent_info) {
	ERR_FAIL_COND_V_MSG(SteamHTTP() == NULL, false, "[STEAM SERVER] HTTP class not found when calling: setHTTPRequestNetworkActivityTimeout");
	return SteamHTTP()->SetHTTPRequestUserAgentInfo(request_handle, user_agent_info.utf8().get_data());
}


///// INVENTORY

///// When dealing with any inventory handles, you should call CheckResultSteamID on the result handle when it completes to verify that a remote player is not pretending to have a different user's inventory.
///// Also, you must call DestroyResult on the provided inventory result when you are done with it.

// Grant a specific one-time promotional item to the current user.
int32 SteamServer::addPromoItem(uint32 item) {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: addPromoItem");
	if (SteamInventory()->AddPromoItem(&new_inventory_handle, item)) {
		inventory_handle = new_inventory_handle;
	}
	return new_inventory_handle;
}

// Grant a specific one-time promotional items to the current user.
int32 SteamServer::addPromoItems(PoolIntArray items) {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: addPromoItems");
	int count = items.size();
	SteamItemDef_t *new_items = new SteamItemDef_t[items.size()];
	for (int i = 0; i < count; i++) {
		new_items[i] = items[i];
	}
	if (SteamInventory()->AddPromoItems(&new_inventory_handle, new_items, count)) {
		inventory_handle = new_inventory_handle;
	}
	delete[] new_items;
	return new_inventory_handle;
}

// Checks whether an inventory result handle belongs to the specified Steam ID.
bool SteamServer::checkResultSteamID(uint64_t steam_id_expected, int32 this_inventory_handle) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, false, "[STEAM SERVER] Inventory class not found when calling: checkResultSteamID");
	CSteamID steam_id = (uint64)steam_id_expected;
	
	if (this_inventory_handle == 0) {
		this_inventory_handle = inventory_handle;
	}
	return SteamInventory()->CheckResultSteamID((SteamInventoryResult_t)this_inventory_handle, steam_id);
}

// Consumes items from a user's inventory. If the quantity of the given item goes to zero, it is permanently removed.
int32 SteamServer::consumeItem(uint64_t item_consume, uint32 quantity) {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: consumeItem");
	if (SteamInventory()->ConsumeItem(&new_inventory_handle, (SteamItemInstanceID_t)item_consume, quantity)) {
		inventory_handle = new_inventory_handle;
	}
	return new_inventory_handle;
}

// Deserializes a result set and verifies the signature bytes.
int32 SteamServer::deserializeResult(PoolByteArray buffer) {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, 0, "[STEAM SERVER] Inventory class not found when calling: deserializeResult");
	if (SteamInventory()->DeserializeResult(&new_inventory_handle, &buffer, buffer.size(), false)) {
		inventory_handle = new_inventory_handle;
	}
	return new_inventory_handle;
}

// Destroys a result handle and frees all associated memory.
void SteamServer::destroyResult(int this_inventory_handle) {
	ERR_FAIL_COND_MSG(SteamInventory() == NULL, "[STEAM SERVER] Inventory class not found when calling: destroyResult");
	if (this_inventory_handle == 0) {
		this_inventory_handle = inventory_handle;
	}
	SteamInventory()->DestroyResult((SteamInventoryResult_t)this_inventory_handle);
}

// Grant one item in exchange for a set of other items.
int32 SteamServer::exchangeItems(const PoolIntArray output_items, const PoolIntArray output_quantity, const PoolIntArray input_items, const PoolIntArray input_quantity) {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: exchangeItems");
	uint32 total_output = output_items.size();
	SteamItemDef_t *generated_items = new SteamItemDef_t[total_output];
	for (uint32 i = 0; i < total_output; i++) {
		generated_items[i] = output_items[i];
	}

	uint32_t *quantity_out = (uint32*) output_quantity.read().ptr();
	uint32_t *quantity_in = (uint32*) input_quantity.read().ptr();

	uint32 array_size = input_items.size();
	SteamItemInstanceID_t *input_item_ids = new SteamItemInstanceID_t[array_size];
	for (uint32 i = 0; i < array_size; i++) {
		input_item_ids[i] = input_items[i];
	}
	const SteamItemInstanceID_t *these_item_ids = input_item_ids;

	if (SteamInventory()->ExchangeItems(&new_inventory_handle, generated_items, quantity_out, total_output, these_item_ids, quantity_in, array_size)) {
		inventory_handle = new_inventory_handle;
	}
	delete[] generated_items;
	delete[] input_item_ids;
	return new_inventory_handle;
}

// Grants specific items to the current user, for developers only.
int32 SteamServer::generateItems(const PoolIntArray items, const PoolIntArray quantity) {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: generateItems");
	uint32 total_quantity = items.size();
	SteamItemDef_t *generated_items = new SteamItemDef_t[total_quantity];

	for (uint32 i = 0; i < total_quantity; i++) {
		generated_items[i] = items[i];
	}

	uint32_t *this_quantity = (uint32*) quantity.read().ptr();
	if (SteamInventory()->GenerateItems(&new_inventory_handle, generated_items, this_quantity, items.size())) {
		inventory_handle = new_inventory_handle;
	}
	delete[] generated_items;
	return new_inventory_handle;
}

// Start retrieving all items in the current users inventory.
int32 SteamServer::getAllItems() {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: getAllItems");
	if (SteamInventory()->GetAllItems(&new_inventory_handle)) {
		inventory_handle = new_inventory_handle;
	}
	return new_inventory_handle;
}

// Gets a string property from the specified item definition.  Gets a property value for a specific item definition.
String SteamServer::getItemDefinitionProperty(uint32 definition, const String &name) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, "", "[STEAM SERVER] Inventory class not found when calling: getItemDefinitionProperty");
	uint32 buffer_size = STEAM_BUFFER_SIZE;
	char *buffer = new char[buffer_size];
	SteamInventory()->GetItemDefinitionProperty(definition, name.utf8().get_data(), buffer, &buffer_size);
	String property = String::utf8(buffer, buffer_size);
	return property;
}

// After a successful call to RequestPrices, you can call this method to get the pricing for a specific item definition.
Dictionary SteamServer::getItemPrice(uint32 definition) {
	Dictionary prices;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, prices, "[STEAM SERVER] Inventory class not found when calling: getItemPrice");
	uint64 price = 0;
	uint64 base_price = 0;
	SteamInventory()->GetItemPrice(definition, &price, &base_price);
	prices["price"] = (uint64_t)price;
	prices["base_price"] = (uint64_t)base_price;
	return prices;
}

// Gets the state of a subset of the current user's inventory.
int32 SteamServer::getItemsByID(const PoolIntArray id_array) {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: getItemsByID");
	uint32 array_size = id_array.size();
	SteamItemInstanceID_t *item_ids = new SteamItemInstanceID_t[array_size];

	for (uint32 i = 0; i < array_size; i++) {
		item_ids[i] = id_array[i];
	}
	const SteamItemInstanceID_t *these_item_ids = item_ids;

	if (SteamInventory()->GetItemsByID(&new_inventory_handle, these_item_ids, array_size)) {
		inventory_handle = new_inventory_handle;
	}
	delete[] item_ids;
	return new_inventory_handle;
}

// After a successful call to RequestPrices, you can call this method to get all the pricing for applicable item definitions. Use the result of GetNumItemsWithPrices as the the size of the arrays that you pass in.
Array SteamServer::getItemsWithPrices() {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, Array(), "[STEAM SERVER] Inventory class not found when calling: getItemsWithPrices");
	uint32 valid_prices = SteamInventory()->GetNumItemsWithPrices();
	Array price_array;
	SteamItemDef_t *ids = new SteamItemDef_t[valid_prices];
	uint64 *prices = new uint64[valid_prices];
	uint64 *base_prices = new uint64[valid_prices];

	if (SteamInventory()->GetItemsWithPrices(ids, prices, base_prices, valid_prices)) {
		for (uint32 i = 0; i < valid_prices; i++) {
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

// Gets the dynamic properties from an item in an inventory result set.
String SteamServer::getResultItemProperty(uint32 index, const String &name, int32 this_inventory_handle) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, "", "[STEAM SERVER] Inventory class not found when calling: getResultItemProperty");
	uint32 buffer_size = 256;
	char *value = new char[buffer_size];

	if (this_inventory_handle == 0) {
		this_inventory_handle = inventory_handle;
	}

	if (name.empty()) {
		SteamInventory()->GetResultItemProperty((SteamInventoryResult_t)this_inventory_handle, index, NULL, value, &buffer_size);
	}
	else {
		SteamInventory()->GetResultItemProperty((SteamInventoryResult_t)this_inventory_handle, index, name.utf8().get_data(), value, &buffer_size);
	}
	return String::utf8(value, buffer_size);
}

// Get the items associated with an inventory result handle.
Array SteamServer::getResultItems(int32 this_inventory_handle) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, Array(), "[STEAM SERVER] Inventory class not found when calling: getResultItems");
	Array items;
	uint32 size = 0;

	if (SteamInventory()->GetResultItems((SteamInventoryResult_t)this_inventory_handle, NULL, &size)) {
		SteamItemDetails_t *item_array = new SteamItemDetails_t[size];
		if (this_inventory_handle == 0) {
			this_inventory_handle = inventory_handle;
		}
		if (SteamInventory()->GetResultItems((SteamInventoryResult_t)this_inventory_handle, item_array, &size)) {
			for (uint32 i = 0; i < size; i++) {
				Dictionary item_info;
				item_info["item_id"] = (uint64_t)item_array[i].m_itemId;
				item_info["item_definition"] = item_array[i].m_iDefinition;
				item_info["flags"] = item_array[i].m_unFlags;
				item_info["quantity"] = item_array[i].m_unQuantity;
				items.append(item_info);
			}
		}
		delete[] item_array;
	}
	return items;
}

// Find out the status of an asynchronous inventory result handle.
Result SteamServer::getResultStatus(int32 this_inventory_handle) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, RESULT_FAIL, "[STEAM SERVER] Inventory class not found when calling: getResultStatus");
	if (this_inventory_handle == 0) {
		this_inventory_handle = inventory_handle;
	}
	return (Result)SteamInventory()->GetResultStatus((SteamInventoryResult_t)this_inventory_handle);
}

// Gets the server time at which the result was generated.
uint32 SteamServer::getResultTimestamp(int32 this_inventory_handle) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, 0, "[STEAM SERVER] Inventory class not found when calling: getResultTimestamp");
	if (this_inventory_handle == 0) {
		this_inventory_handle = inventory_handle;
	}
	return SteamInventory()->GetResultTimestamp((SteamInventoryResult_t)this_inventory_handle);
}

// Grant all potential one-time promotional items to the current user.
int32 SteamServer::grantPromoItems() {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: grantPromoItems");
	if (SteamInventory()->GrantPromoItems(&new_inventory_handle)) {
		inventory_handle = new_inventory_handle;
	}
	return new_inventory_handle;
}

// Triggers an asynchronous load and refresh of item definitions.
bool SteamServer::loadItemDefinitions() {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, false, "[STEAM SERVER] Inventory class not found when calling: loadItemDefinitions");
	return SteamInventory()->LoadItemDefinitions();
}

// Removes a dynamic property for the given item.
bool SteamServer::removeProperty(uint64_t item_id, const String &name, uint64_t this_inventory_update_handle) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, false, "[STEAM SERVER] Inventory class not found when calling: removeProperty");
	if (this_inventory_update_handle == 0) {
		this_inventory_update_handle = inventory_update_handle;
	}
	return SteamInventory()->RemoveProperty((SteamInventoryUpdateHandle_t)this_inventory_update_handle, (SteamItemInstanceID_t)item_id, name.utf8().get_data());
}

// Request the list of "eligible" promo items that can be manually granted to the given user.
void SteamServer::requestEligiblePromoItemDefinitionsIDs(uint64_t steam_id) {
	ERR_FAIL_COND_MSG(SteamInventory() == NULL, "[STEAM SERVER] Inventory class not found when calling: requestEligiblePromoItemDefinitionsIDs");
	CSteamID user_id = (uint64)steam_id;
	SteamAPICall_t api_call = SteamInventory()->RequestEligiblePromoItemDefinitionsIDs(user_id);
	callResultEligiblePromoItemDefIDs.Set(api_call, this, &SteamServer::inventory_eligible_promo_item);
}

// Request prices for all item definitions that can be purchased in the user's local currency. A SteamInventoryRequestPricesResult_t call result will be returned with the user's local currency code. After that, you can call GetNumItemsWithPrices and GetItemsWithPrices to get prices for all the known item definitions, or GetItemPrice for a specific item definition.
void SteamServer::requestPrices() {
	ERR_FAIL_COND_MSG(SteamInventory() == NULL, "[STEAM SERVER] Inventory class not found when calling: requestPrices");
	SteamAPICall_t api_call = SteamInventory()->RequestPrices();
	callResultRequestPrices.Set(api_call, this, &SteamServer::inventory_request_prices_result);
}

// Serialized result sets contain a short signature which can't be forged or replayed across different game sessions.
PoolByteArray SteamServer::serializeResult(int32 this_inventory_handle) {
	PoolByteArray result_serialized;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, result_serialized, "[STEAM SERVER] Inventory class not found when calling: serializeResult");
	if (this_inventory_handle == 0) {
		this_inventory_handle = inventory_handle;
	}

	uint32 buffer_size = STEAM_BUFFER_SIZE;
	PoolByteArray buffer;
	buffer.resize(buffer_size);
	if (SteamInventory()->SerializeResult((SteamInventoryResult_t)this_inventory_handle, buffer.write().ptr(), &buffer_size)) {
		buffer.resize(buffer_size);
		result_serialized = buffer;
	}
	return result_serialized;
}

// Sets a dynamic property for the given item. Supported value types are boolean.
bool SteamServer::setPropertyBool(uint64_t item_id, const String &name, bool value, uint64_t this_inventory_update_handle) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, false, "[STEAM SERVER] Inventory class not found when calling: setPropertyBool");
	if (this_inventory_update_handle == 0) {
		this_inventory_update_handle = inventory_update_handle;
	}
	return SteamInventory()->SetProperty((SteamInventoryUpdateHandle_t)this_inventory_update_handle, (SteamItemInstanceID_t)item_id, name.utf8().get_data(), value);
}

// Sets a dynamic property for the given item. Supported value types are 32 bit floats.
bool SteamServer::setPropertyFloat(uint64_t item_id, const String &name, float value, uint64_t this_inventory_update_handle) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, false, "[STEAM SERVER] Inventory class not found when calling: setPropertyFloat");
	if (this_inventory_update_handle == 0) {
		this_inventory_update_handle = inventory_update_handle;
	}
	return SteamInventory()->SetProperty((SteamInventoryUpdateHandle_t)this_inventory_update_handle, (SteamItemInstanceID_t)item_id, name.utf8().get_data(), value);
}

// Sets a dynamic property for the given item. Supported value types are 64 bit integers.
bool SteamServer::setPropertyInt(uint64_t item_id, const String &name, uint64_t value, uint64_t this_inventory_update_handle) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, false, "[STEAM SERVER] Inventory class not found when calling: setPropertyInt");
	if (this_inventory_update_handle == 0) {
		this_inventory_update_handle = inventory_update_handle;
	}
	return SteamInventory()->SetProperty((SteamInventoryUpdateHandle_t)this_inventory_update_handle, (SteamItemInstanceID_t)item_id, name.utf8().get_data(), (int64)value);
}

// Sets a dynamic property for the given item. Supported value types are strings.
bool SteamServer::setPropertyString(uint64_t item_id, const String &name, const String &value, uint64_t this_inventory_update_handle) {
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, false, "[STEAM SERVER] Inventory class not found when calling: setPropertyString");
	if (this_inventory_update_handle == 0) {
		this_inventory_update_handle = inventory_update_handle;
	}
	return SteamInventory()->SetProperty((SteamInventoryUpdateHandle_t)this_inventory_update_handle, (SteamItemInstanceID_t)item_id, name.utf8().get_data(), value.utf8().get_data());
}

// Starts the purchase process for the user, given a "shopping cart" of item definitions that the user would like to buy. The user will be prompted in the Steam Overlay to complete the purchase in their local currency, funding their Steam Wallet if necessary, etc.
void SteamServer::startPurchase(const PoolIntArray items, const PoolIntArray quantity) {
	ERR_FAIL_COND_MSG(SteamInventory() == NULL, "[STEAM SERVER] Inventory class not found when calling: startPurchase");
	uint32 total_items = items.size();
	SteamItemDef_t *purchases = new SteamItemDef_t[total_items];
	for (uint32 i = 0; i < total_items; i++) {
		purchases[i] = items[i];
	}

	uint32_t *these_quantities = (uint32*) quantity.read().ptr();
	SteamAPICall_t api_call = SteamInventory()->StartPurchase(purchases, these_quantities, total_items);
	callResultStartPurchase.Set(api_call, this, &SteamServer::inventory_start_purchase_result);
	delete[] purchases;
}

// Starts a transaction request to update dynamic properties on items for the current user. This call is rate-limited by user, so property modifications should be batched as much as possible (e.g. at the end of a map or game session). After calling SetProperty or RemoveProperty for all the items that you want to modify, you will need to call SubmitUpdateProperties to send the request to the Steam servers. A SteamInventoryResultReady_t callback will be fired with the results of the operation.
void SteamServer::startUpdateProperties() {
	ERR_FAIL_COND_MSG(SteamInventory() == NULL, "[STEAM SERVER] Inventory class not found when calling: startUpdateProperties");
	inventory_update_handle = SteamInventory()->StartUpdateProperties();
}

// Submits the transaction request to modify dynamic properties on items for the current user. See StartUpdateProperties.
int32 SteamServer::submitUpdateProperties(uint64_t this_inventory_update_handle) {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: submitUpdateProperties");
	if (this_inventory_update_handle == 0) {
		this_inventory_update_handle = inventory_update_handle;
	}

	if (SteamInventory()->SubmitUpdateProperties((SteamInventoryUpdateHandle_t)this_inventory_update_handle, &new_inventory_handle)) {
		inventory_handle = new_inventory_handle;
	}
	return new_inventory_handle;
}

// Transfer items between stacks within a user's inventory.
int32 SteamServer::transferItemQuantity(uint64_t item_id, uint32 quantity, uint64_t item_destination, bool split) {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: transferItemQuantity");
	if (split) {
		if (SteamInventory()->TransferItemQuantity(&new_inventory_handle, (SteamItemInstanceID_t)item_id, quantity, k_SteamItemInstanceIDInvalid)) {
			inventory_handle = new_inventory_handle;
		}
	}
	else {
		if (SteamInventory()->TransferItemQuantity(&new_inventory_handle, (SteamItemInstanceID_t)item_id, quantity, (SteamItemInstanceID_t)item_destination)) {
			inventory_handle = new_inventory_handle;
		}
	}
	return new_inventory_handle;
}

// Trigger an item drop if the user has played a long enough period of time.
int32 SteamServer::triggerItemDrop(uint32 definition) {
	int32 new_inventory_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamInventory() == NULL, new_inventory_handle, "[STEAM SERVER] Inventory class not found when calling: triggerItemDrop");
	if (SteamInventory()->TriggerItemDrop(&new_inventory_handle, (SteamItemDef_t)definition)) {
		inventory_handle = new_inventory_handle;
	}
	return new_inventory_handle;
}


///// NETWORKING

// This allows the game to specify accept an incoming packet.
bool SteamServer::acceptP2PSessionWithUser(uint64_t remote_steam_id) {
	ERR_FAIL_COND_V_MSG(SteamNetworking() == NULL, false, "[STEAM SERVER] Game Server class not found when calling: acceptP2PSessionWithUser");
	CSteamID steam_id = createSteamID(remote_steam_id);
	return SteamNetworking()->AcceptP2PSessionWithUser(steam_id);
}

// Allow or disallow P2P connections to fall back to being relayed through the Steam servers if a direct connection or NAT-traversal cannot be established.
bool SteamServer::allowP2PPacketRelay(bool allow) {
	ERR_FAIL_COND_V_MSG(SteamNetworking() == NULL, false, "[STEAM SERVER] Game Server class not found when calling: allowP2PPacketRelay");
	return SteamNetworking()->AllowP2PPacketRelay(allow);
}

// Closes a P2P channel when you're done talking to a user on the specific channel.
bool SteamServer::closeP2PChannelWithUser(uint64_t remote_steam_id, int channel) {
	ERR_FAIL_COND_V_MSG(SteamNetworking() == NULL, false, "[STEAM SERVER] Game Server class not found when calling: closeP2PChannelWithUser");
	CSteamID steam_id = createSteamID(remote_steam_id);
	return SteamNetworking()->CloseP2PChannelWithUser(steam_id, channel);
}

// This should be called when you're done communicating with a user, as this will free up all of the resources allocated for the connection under-the-hood.
bool SteamServer::closeP2PSessionWithUser(uint64_t remote_steam_id) {
	ERR_FAIL_COND_V_MSG(SteamNetworking() == NULL, false, "[STEAM SERVER] Game Server class not found when calling: closeP2PSessionWithUser");
	CSteamID steam_id = createSteamID(remote_steam_id);
	return SteamNetworking()->CloseP2PSessionWithUser(steam_id);
}

// Fills out a P2PSessionState_t structure with details about the connection like whether or not there is an active connection.
Dictionary SteamServer::getP2PSessionState(uint64_t remote_steam_id) {
	Dictionary result;
	ERR_FAIL_COND_V_MSG(SteamNetworking() == NULL, result, "[STEAM SERVER] Game Server class not found when calling: getP2PSessionState");
	CSteamID steam_id = createSteamID(remote_steam_id);
	P2PSessionState_t p2pSessionState;
	if (SteamNetworking()->GetP2PSessionState(steam_id, &p2pSessionState)) {
		result["connection_active"] = p2pSessionState.m_bConnectionActive; // true if we've got an active open connection
		result["connecting"] = p2pSessionState.m_bConnecting; // true if we're currently trying to establish a connection
		result["session_error"] = p2pSessionState.m_eP2PSessionError; // last error recorded (see enum in isteamnetworking.h)
		result["using_relay"] = p2pSessionState.m_bUsingRelay; // true if it's going through a relay server (TURN)
		result["bytes_queued_for_send"] = p2pSessionState.m_nBytesQueuedForSend;
		result["packets_queued_for_send"] = p2pSessionState.m_nPacketsQueuedForSend;
		result["remote_ip"] = p2pSessionState.m_nRemoteIP; // potential IP:Port of remote host. Could be TURN server.
		result["remote_port"] = p2pSessionState.m_nRemotePort; // Only exists for compatibility with older authentication api's
	}
	return result;
}

// Calls IsP2PPacketAvailable() under the hood, returns the size of the available packet or zero if there is no such packet.
uint32_t SteamServer::getAvailableP2PPacketSize(int channel) {
	ERR_FAIL_COND_V_MSG(SteamNetworking() == NULL, 0, "[STEAM SERVER] Game Server class not found when calling: getAvailableP2PPacketSize");
	uint32_t message_size = 0;
	return (SteamNetworking()->IsP2PPacketAvailable(&message_size, channel)) ? message_size : 0;
}

// Reads in a packet that has been sent from another user via SendP2PPacket.
Dictionary SteamServer::readP2PPacket(uint32_t packet, int channel) {
	Dictionary result;
	ERR_FAIL_COND_V_MSG(SteamNetworking() == NULL, result, "[STEAM SERVER] Game Server class not found when calling: readP2PPacket");
	PoolByteArray data;
	data.resize(packet);
	CSteamID steam_id;
	uint32_t bytes_read = 0;
	
	if (SteamNetworking()->ReadP2PPacket(data.write().ptr(), packet, &bytes_read, &steam_id, channel)) {
		data.resize(bytes_read);
		uint64_t remote_steam_id = steam_id.ConvertToUint64();
		result["data"] = data;
		result["remote_steam_id"] = remote_steam_id;
	}
	else {
		data.resize(0);
	}
	return result;
}

// Sends a P2P packet to the specified user.
bool SteamServer::sendP2PPacket(uint64_t remote_steam_id, PoolByteArray data, P2PSend send_type, int channel) {
	ERR_FAIL_COND_V_MSG(SteamNetworking() == NULL, false, "[STEAM SERVER] Networking class not found when calling: sendP2PPacket");
	CSteamID steam_id = createSteamID(remote_steam_id);
	return SteamNetworking()->SendP2PPacket(steam_id, data.read().ptr(), data.size(), EP2PSend(send_type), channel);
}


///// NETWORKING MESSAGES

// AcceptSessionWithUser() should only be called in response to a SteamP2PSessionRequest_t callback SteamP2PSessionRequest_t will be posted if another user tries to send you a message, and you haven't tried to talk to them.
bool SteamServer::acceptSessionWithUser(uint64_t remote_steam_id) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] Networking Messages class not found when calling: acceptSessionWithUser");
	return SteamNetworkingMessages()->AcceptSessionWithUser(getIdentityFromSteamID(remote_steam_id));
}

// Call this  when you're done talking to a user on a specific channel. Once all open channels to a user have been closed, the open session to the user will be closed, and any new data from this user will trigger a SteamP2PSessionRequest_t callback.
bool SteamServer::closeChannelWithUser(uint64_t remote_steam_id, int channel) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] Networking Messages class not found when calling: closeChannelWithUser");
	return SteamNetworkingMessages()->CloseChannelWithUser(getIdentityFromSteamID(remote_steam_id), channel);
}

// Call this when you're done talking to a user to immediately free up resources under-the-hood.
bool SteamServer::closeSessionWithUser(uint64_t remote_steam_id) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] Networking Messages class not found when calling: closeSessionWithUser");
	return SteamNetworkingMessages()->CloseSessionWithUser(getIdentityFromSteamID(remote_steam_id));
}

// Returns information about the latest state of a connection, if any, with the given peer.
Dictionary SteamServer::getSessionConnectionInfo(uint64_t remote_steam_id, bool get_connection, bool get_status) {
	Dictionary connection_info;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, connection_info, "[STEAM SERVER] Networking Messages class not found when calling: getSessionConnectionInfo");
	SteamNetConnectionInfo_t this_info;
	SteamNetConnectionRealTimeStatus_t this_status;
	int connection_state = SteamNetworkingMessages()->GetSessionConnectionInfo(getIdentityFromSteamID(remote_steam_id), &this_info, &this_status);
	// Parse the data to a dictionary
	connection_info["connection_state"] = connection_state;

	// If getting the connection information
	if (get_connection) {
		connection_info["identity"] = getSteamIDFromIdentity(this_info.m_identityRemote);
		connection_info["user_data"] = (uint64_t)this_info.m_nUserData;
		connection_info["listen_socket"] = this_info.m_hListenSocket;
		connection_info["remote_address"] = getStringFromSteamIP(this_info.m_addrRemote);
		connection_info["remote_pop"] = this_info.m_idPOPRemote;
		connection_info["pop_relay"] = this_info.m_idPOPRelay;
		connection_info["connection_state"] = this_info.m_eState;
		connection_info["end_reason"] = this_info.m_eEndReason;
		connection_info["end_debug"] = this_info.m_szEndDebug;
		connection_info["debug_description"] = this_info.m_szConnectionDescription;
		connection_info["info_flags"] = this_info.m_nFlags;
	}

	// If getting the quick status
	if (get_status) {
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
	return connection_info;
}

// Reads the next message that has been sent from another user via SendMessageToUser() on the given channel. Returns number of messages returned into your list.  (0 if no message are available on that channel.)
Array SteamServer::receiveMessagesOnChannel(int channel, int max_messages) {
	Array messages;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, messages, "[STEAM SERVER] Networking Messages class not found when calling: receiveMessagesOnChannel");
	// Allocate the space for the messages
	SteamNetworkingMessage_t **channel_messages = new SteamNetworkingMessage_t *[max_messages];
	// Get the messages
	int available_messages = SteamNetworkingMessages()->ReceiveMessagesOnChannel(channel, channel_messages, max_messages);

	// Loop through and create the messages as dictionaries then add to the messages array
	for (int i = 0; i < available_messages; i++) {
		// Set up the mesage dictionary
		Dictionary message;
		// Get the data / message
		int message_size = channel_messages[i]->m_cbSize;
		PoolByteArray data;
		data.resize(message_size);
		uint8_t *source_data = (uint8_t *)channel_messages[i]->m_pData;
		uint8_t *output_data = data.write().ptr();
		for (int j = 0; j < message_size; j++) {
			output_data[j] = source_data[j];
		}
		message["payload"] = data;
		message["size"] = message_size;
		message["connection"] = channel_messages[i]->m_conn;
		message["identity"] = getSteamIDFromIdentity(channel_messages[i]->m_identityPeer);
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
	delete[] channel_messages;
	return messages;
}

// Sends a message to the specified host. If we don't already have a session with that user, a session is implicitly created. There might be some handshaking that needs to happen before we can actually begin sending message data.
int SteamServer::sendMessageToUser(uint64_t remote_steam_id, const PoolByteArray data, int flags, int channel) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, 0, "[STEAM SERVER] Networking Messages class not found when calling: sendMessageToUser");
	return SteamNetworkingMessages()->SendMessageToUser(getIdentityFromSteamID(remote_steam_id), data.read().ptr(), data.size(), flags, channel);
}


///// NETWORKING SOCKETS

// Creates a "server" socket that listens for clients to connect to by calling ConnectByIPAddress, over ordinary UDP (IPv4 or IPv6)
uint32 SteamServer::createListenSocketIP(String ip_address, Dictionary config_options) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: createListenSocketIP");
	uint32 listen_socket = SteamNetworkingSockets()->CreateListenSocketIP(getSteamIPFromString(ip_address), config_options.size(), convert_config_options(config_options));
	return listen_socket;
}

// Like CreateListenSocketIP, but clients will connect using ConnectP2P. The connection will be relayed through the Valve network.
uint32 SteamServer::createListenSocketP2P(int virtual_port, Dictionary config_options) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: createListenSocketP2P");
	uint32 listen_socket = SteamNetworkingSockets()->CreateListenSocketP2P(virtual_port, config_options.size(), convert_config_options(config_options));
	return listen_socket;
}

// Begin connecting to a server that is identified using a platform-specific identifier. This uses the default rendezvous service, which depends on the platform and library configuration. (E.g. on Steam, it goes through the steam backend.) The traffic is relayed over the Steam Datagram Relay network.
uint32 SteamServer::connectP2P(uint64_t remote_steam_id, int virtual_port, Dictionary config_options) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: connectP2P");
	uint32 listen_socket = SteamNetworkingSockets()->ConnectP2P(getIdentityFromSteamID(remote_steam_id), virtual_port, config_options.size(), convert_config_options(config_options));
	return listen_socket;
}

// Begin connecting to a server listen socket that is identified using an [ip-address]:[port], i.e. 127.0.0.1:27015. Used with createListenSocketIP
uint32 SteamServer::connectByIPAddress(String ip_address_with_port, Dictionary config_options) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: connectByIPAddress");
	return SteamNetworkingSockets()->ConnectByIPAddress(getSteamIPFromString(ip_address_with_port), config_options.size(), convert_config_options(config_options));
}

// Client call to connect to a server hosted in a Valve data center, on the specified virtual port. You must have placed a ticket for this server into the cache, or else this connect attempt will fail!
uint32 SteamServer::connectToHostedDedicatedServer(uint64_t remote_steam_id, int virtual_port, Dictionary config_options) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: connectToHostedDedicatedServer");
	uint32 listen_socket = SteamNetworkingSockets()->ConnectToHostedDedicatedServer(getIdentityFromSteamID(remote_steam_id), virtual_port, config_options.size(), convert_config_options(config_options));
	return listen_socket;
}

// Accept an incoming connection that has been received on a listen socket.
int SteamServer::acceptConnection(uint32 connection_handle) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: acceptConnection");
	return SteamNetworkingSockets()->AcceptConnection((HSteamNetConnection)connection_handle);
}

// Disconnects from the remote host and invalidates the connection handle. Any unread data on the connection is discarded.
bool SteamServer::closeConnection(uint32 peer, int reason, const String &debug_message, bool linger) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, false, "[STEAM SERVER] Networking Sockets class not found when calling: closeConnection");
	return SteamNetworkingSockets()->CloseConnection((HSteamNetConnection)peer, reason, debug_message.utf8().get_data(), linger);
}

// Destroy a listen socket. All the connections that were accepted on the listen socket are closed ungracefully.
bool SteamServer::closeListenSocket(uint32 socket) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, false, "[STEAM SERVER] Networking Sockets class not found when calling: closeListenSocket");
	return SteamNetworkingSockets()->CloseListenSocket((HSteamListenSocket)socket);
}

// Create a pair of connections that are talking to each other, e.g. a loopback connection. This is very useful for testing, or so that your client/server code can work the same even when you are running a local "server".
Dictionary SteamServer::createSocketPair(bool loopback, uint64_t remote_steam_id1, uint64_t remote_steam_id2) {
	Dictionary connection_pair;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, connection_pair, "[STEAM SERVER] Networking Sockets class not found when calling: createSocketPair");
	uint32 connection1 = 0;
	uint32 connection2 = 0;
	SteamNetworkingIdentity remote_identity1 = getIdentityFromSteamID(remote_steam_id1);
	SteamNetworkingIdentity remote_identity2 = getIdentityFromSteamID(remote_steam_id2);
	bool success = SteamNetworkingSockets()->CreateSocketPair(&connection1, &connection2, loopback, &remote_identity1, &remote_identity2);
	// Populate the dictionary
	connection_pair["success"] = success;
	connection_pair["connection1"] = connection1;
	connection_pair["connection2"] = connection2;
	return connection_pair;
}

// Send a message to the remote host on the specified connection.
Dictionary SteamServer::sendMessageToConnection(uint32 connection_handle, const PoolByteArray data, int flags) {
	Dictionary message_response;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, message_response, "[STEAM SERVER] Networking Sockets class not found when calling: sendMessageToConnection");
	int64 number;
	int result = SteamNetworkingSockets()->SendMessageToConnection((HSteamNetConnection)connection_handle, data.read().ptr(), data.size(), flags, &number);
	// Populate the dictionary
	message_response["result"] = result;
	message_response["message_number"] = (uint64_t)number;
	return message_response;
}

// // Send one or more messages without copying the message payload. This is the most efficient way to send messages. To use this function, you must first allocate a message object using ISteamNetworkingUtils::AllocateMessage. (Do not declare one on the stack or allocate your own.)
// void SteamServer::sendMessages(int messages, const PoolByteArray data, uint32 connection_handle, int flags) {
// 	if (SteamNetworkingSockets() != NULL) {
// 		SteamNetworkingMessage_t *networkMessage;
// 		networkMessage = SteamNetworkingUtils()->AllocateMessage(0);
// 		networkMessage->m_pData = (void *)data.read().ptr();
// 		networkMessage->m_cbSize = data.size();
// 		networkMessage->m_conn = (HSteamNetConnection)connection_handle;
// 		networkMessage->m_nFlags = flags;
// 		int64 result;
// 		SteamNetworkingSockets()->SendMessages(messages, &networkMessage, &result);
// 		// Release the message
// 		networkMessage->Release();
// 	}
// }

// Flush any messages waiting on the Nagle timer and send them at the next transmission opportunity (often that means right now).
int SteamServer::flushMessagesOnConnection(uint32 connection_handle) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: flushMessagesOnConnection");
	return SteamNetworkingSockets()->FlushMessagesOnConnection((HSteamNetConnection)connection_handle);
}

// Fetch the next available message(s) from the connection, if any. Returns the number of messages returned into your array, up to nMaxMessages. If the connection handle is invalid, -1 is returned. If no data is available, 0, is returned.
Array SteamServer::receiveMessagesOnConnection(uint32 connection_handle, int max_messages) {
	Array messages;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, messages, "[STEAM SERVER] Networking Sockets class not found when calling: receiveMessagesOnConnection");
	SteamNetworkingMessage_t **connection_messages = new SteamNetworkingMessage_t *[max_messages];
	int available_messages = SteamNetworkingSockets()->ReceiveMessagesOnConnection((HSteamNetConnection)connection_handle, connection_messages, max_messages);

	for (int i = 0; i < available_messages; i++) {
		Dictionary message;
		int message_size = connection_messages[i]->m_cbSize;
		PoolByteArray data;
		data.resize(message_size);
		uint8_t *source_data = (uint8_t *)connection_messages[i]->m_pData;
		uint8_t *output_data = data.write().ptr();

		for (int j = 0; j < message_size; j++) {
			output_data[j] = source_data[j];
		}
		message["payload"] = data;
		message["size"] = message_size;
		message["connection"] = connection_messages[i]->m_conn;
		message["identity"] = getSteamIDFromIdentity(connection_messages[i]->m_identityPeer);
		message["receiver_user_data"] = (uint64_t)connection_messages[i]->m_nConnUserData;	// Not used when sending messages
		message["time_received"] = (uint64_t)connection_messages[i]->m_usecTimeReceived;
		message["message_number"] = (uint64_t)connection_messages[i]->m_nMessageNumber;
		message["channel"] = connection_messages[i]->m_nChannel;
		message["flags"] = connection_messages[i]->m_nFlags;
		message["sender_user_data"] = (uint64_t)connection_messages[i]->m_nUserData;	// Not used when receiving messages
		messages.append(message);
		// Release the message
		connection_messages[i]->Release();
	}
	delete[] connection_messages;
	return messages;
}

// Create a new poll group.
uint32 SteamServer::createPollGroup() {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: createPollGroup");
	return SteamNetworkingSockets()->CreatePollGroup();
}

// Destroy a poll group created with CreatePollGroup.
bool SteamServer::destroyPollGroup(uint32 poll_group) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, false, "[STEAM SERVER] Networking Sockets class not found when calling: destroyPollGroup");
	return SteamNetworkingSockets()->DestroyPollGroup((HSteamNetPollGroup)poll_group);
}

// Assign a connection to a poll group. Note that a connection may only belong to a single poll group. Adding a connection to a poll group implicitly removes it from any other poll group it is in.
bool SteamServer::setConnectionPollGroup(uint32 connection_handle, uint32 poll_group) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, false, "[STEAM SERVER] Networking Sockets class not found when calling: setConnectionPollGroup");
	return SteamNetworkingSockets()->SetConnectionPollGroup((HSteamNetConnection)connection_handle, (HSteamNetPollGroup)poll_group);
}

// Same as ReceiveMessagesOnConnection, but will return the next messages available on any connection in the poll group. Examine SteamNetworkingMessage_t::m_conn to know which connection. (SteamNetworkingMessage_t::m_nConnUserData might also be useful.)
Array SteamServer::receiveMessagesOnPollGroup(uint32 poll_group, int max_messages) {
	Array messages;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, messages, "[STEAM SERVER] Networking Sockets class not found when calling: receiveMessagesOnPollGroup");
	SteamNetworkingMessage_t **poll_messages = new SteamNetworkingMessage_t *[max_messages];
	int available_messages = SteamNetworkingSockets()->ReceiveMessagesOnPollGroup((HSteamNetPollGroup)poll_group, poll_messages, max_messages);

	for (int i = 0; i < available_messages; i++) {
		Dictionary message;

		int message_size = poll_messages[i]->m_cbSize;
		PoolByteArray data;
		data.resize(message_size);
		uint8_t *source_data = (uint8_t*)poll_messages[i]->m_pData;
		uint8_t *output_data = data.write().ptr();
		for (int j = 0; j < message_size; j++) {
			output_data[j] = source_data[j];
		}

		message["payload"] = data;
		message["size"] = message_size;
		message["connection"] = poll_messages[i]->m_conn;
		message["identity"] = getSteamIDFromIdentity(poll_messages[i]->m_identityPeer);
		message["receiver_user_data"] = (uint64_t)poll_messages[i]->m_nConnUserData;	// Not used when sending messages
		message["time_received"] = (uint64_t)poll_messages[i]->m_usecTimeReceived;
		message["message_number"] = (uint64_t)poll_messages[i]->m_nMessageNumber;
		message["channel"] = poll_messages[i]->m_nChannel;
		message["flags"] = poll_messages[i]->m_nFlags;
		message["sender_user_data"] = (uint64_t)poll_messages[i]->m_nUserData;	// Not used when receiving messages
		messages.append(message);

		poll_messages[i]->Release();
	}
	delete [] poll_messages;
	return messages;
}

// Returns basic information about the high-level state of the connection. Returns false if the connection handle is invalid.
Dictionary SteamServer::getConnectionInfo(uint32 connection_handle) {
	Dictionary connection_info;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, connection_info, "[STEAM SERVER] Networking Sockets class not found when calling: getConnectionInfo");
	SteamNetConnectionInfo_t info;
	if (SteamNetworkingSockets()->GetConnectionInfo((HSteamNetConnection)connection_handle, &info)) {
		connection_info["identity"] = getSteamIDFromIdentity(info.m_identityRemote);
		connection_info["user_data"] = (uint64_t)info.m_nUserData;
		connection_info["listen_socket"] = info.m_hListenSocket;
		connection_info["remote_address"] = getStringFromSteamIP(info.m_addrRemote);
		connection_info["remote_pop"] = info.m_idPOPRemote;
		connection_info["pop_relay"] = info.m_idPOPRelay;
		connection_info["connection_state"] = info.m_eState;
		connection_info["end_reason"] = info.m_eEndReason;
		connection_info["end_debug"] = info.m_szEndDebug;
		connection_info["debug_description"] = info.m_szConnectionDescription;
		connection_info["info_flags"] = info.m_nFlags;
	}
	return connection_info;
}

// Returns very detailed connection stats in diagnostic text format. Useful for dumping to a log, etc. The format of this information is subject to change.
Dictionary SteamServer::getDetailedConnectionStatus(uint32 connection) {
	Dictionary connection_status;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, connection_status, "[STEAM SERVER] Networking Sockets class not found when calling: getDetailedConnectionStatus");
	char buffer[STEAM_LARGE_BUFFER_SIZE];
	int success = SteamNetworkingSockets()->GetDetailedConnectionStatus((HSteamNetConnection)connection, buffer, STEAM_LARGE_BUFFER_SIZE);

	connection_status["success"] = success;
	connection_status["status"] = buffer;
	return connection_status;
}

// Fetch connection user data. Returns -1 if handle is invalid or if you haven't set any userdata on the connection.
uint64_t SteamServer::getConnectionUserData(uint32 peer) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: getConnectionUserData");
	return SteamNetworkingSockets()->GetConnectionUserData((HSteamNetConnection)peer);
}

// Set a name for the connection, used mostly for debugging
void SteamServer::setConnectionName(uint32 peer, const String &name) {
	ERR_FAIL_COND_MSG(SteamNetworkingSockets() == NULL, "[STEAM SERVER] Networking Sockets class not found when calling: setConnectionName");
	SteamNetworkingSockets()->SetConnectionName((HSteamNetConnection)peer, name.utf8().get_data());
}

// Fetch connection name into your buffer, which is at least nMaxLen bytes. Returns false if handle is invalid.
String SteamServer::getConnectionName(uint32 peer) {
	String connection_name = "";
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, connection_name, "[STEAM SERVER] Networking Sockets class not found when calling: getConnectionName");
	char name[STEAM_BUFFER_SIZE];
	if (SteamNetworkingSockets()->GetConnectionName((HSteamNetConnection)peer, name, STEAM_BUFFER_SIZE)) {
		connection_name += name;
	}
	return connection_name;
}

// Returns local IP and port that a listen socket created using CreateListenSocketIP is bound to.
String SteamServer::getListenSocketAddress(uint32 socket, bool with_port) {
	String socket_address = "";
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, socket_address, "[STEAM SERVER] Networking Sockets class not found when calling: getListenSocketAddress");
	SteamNetworkingIPAddr address;
	if (SteamNetworkingSockets()->GetListenSocketAddress((HSteamListenSocket)socket, &address)) {
		socket_address = getStringFromSteamIP(address);
	}
	return socket_address;
}

// Indicate our desire to be ready participate in authenticated communications. If we are currently not ready, then steps will be taken to obtain the necessary certificates. (This includes a certificate for us, as well as any CA certificates needed to authenticate peers.)
NetworkingAvailability SteamServer::initAuthentication() {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, NETWORKING_AVAILABILITY_UNKNOWN, "[STEAM SERVER] Networking Sockets class not found when calling: initAuthentication");
	return NetworkingAvailability(SteamNetworkingSockets()->InitAuthentication());
}

// Query our readiness to participate in authenticated communications. A SteamNetAuthenticationStatus_t callback is posted any time this status changes, but you can use this function to query it at any time.
NetworkingAvailability SteamServer::getAuthenticationStatus() {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, NETWORKING_AVAILABILITY_UNKNOWN, "[STEAM SERVER] Networking Sockets class not found when calling: getAuthenticationStatus");
	return NetworkingAvailability(SteamNetworkingSockets()->GetAuthenticationStatus(NULL));
}

// Call this when you receive a ticket from your backend / matchmaking system. Puts the ticket into a persistent cache, and optionally returns the parsed ticket.
//Dictionary SteamServer::receivedRelayAuthTicket() {
//	Dictionary ticket;
//	if (SteamNetworkingSockets() != NULL) {
//		SteamDatagramRelayAuthTicket parsed_ticket;
//		PoolByteArray incoming_ticket;
//		incoming_ticket.resize(512);
//		if (SteamNetworkingSockets()->ReceivedRelayAuthTicket(incoming_ticket.write().ptr(), 512, &parsed_ticket)) {
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
//int SteamServer::findRelayAuthTicketForServer(int port) {
//	int expires_in_seconds = 0;
//	if (SteamNetworkingSockets() != NULL) {
//		expires_in_seconds = SteamNetworkingSockets()->FindRelayAuthTicketForServer(game_server, port, &relay_auth_ticket);
//	}
//	return expires_in_seconds;
//}

// Returns the value of the SDR_LISTEN_PORT environment variable. This is the UDP server your server will be listening on. This will configured automatically for you in production environments.
uint16 SteamServer::getHostedDedicatedServerPort() {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: getHostedDedicatedServerPort");
	return SteamNetworkingSockets()->GetHostedDedicatedServerPort();
}

// Returns 0 if SDR_LISTEN_PORT is not set. Otherwise, returns the data center the server is running in. This will be k_SteamDatagramPOPID_dev in non-production environment.
uint32 SteamServer::getHostedDedicatedServerPOPId() {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: getHostedDedicatedServerPOPId");
	return SteamNetworkingSockets()->GetHostedDedicatedServerPOPID();
}

// Return info about the hosted server. This contains the PoPID of the server, and opaque routing information that can be used by the relays to send traffic to your server.
//int SteamServer::getHostedDedicatedServerAddress() {
//	int result = 2;
//	if (SteamNetworkingSockets() != NULL) {
//		result = SteamNetworkingSockets()->GetHostedDedicatedServerAddress(&hosted_address);
//	}
//	return result;
//}

// Create a listen socket on the specified virtual port. The physical UDP port to use will be determined by the SDR_LISTEN_PORT environment variable. If a UDP port is not configured, this call will fail.
uint32 SteamServer::createHostedDedicatedServerListenSocket(int port, Dictionary config_options) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: createHostedDedicatedServerListenSocket");
	uint32 listen_socket = SteamGameServerNetworkingSockets()->CreateHostedDedicatedServerListenSocket(port, config_options.size(), convert_config_options(config_options));
	return listen_socket;
}

// Generate an authentication blob that can be used to securely login with your backend, using SteamDatagram_ParseHostedServerLogin. (See steamdatagram_gamecoordinator.h)
//int SteamServer::getGameCoordinatorServerLogin(const String &app_data) {
//	int result = 2;
//	if (SteamNetworkingSockets() != NULL) {
//		SteamDatagramGameCoordinatorServerLogin *server_login = new SteamDatagramGameCoordinatorServerLogin;
//		server_login->m_cbAppData = app_data.size();
//		strcpy(server_login->m_appData, app_data.utf8().get_data());
//		int signed_blob = k_cbMaxSteamDatagramGameCoordinatorServerLoginSerialized;
//		routing_blob.resize(signed_blob);
//		result = SteamNetworkingSockets()->GetGameCoordinatorServerLogin(server_login, &signed_blob, routing_blob.write().ptr());
//		delete server_login;
//	}
//	return result;
//}

// Returns a small set of information about the real-time state of the connection and the queue status of each lane.
Dictionary SteamServer::getConnectionRealTimeStatus(uint32 connection, int lanes, bool get_status) {
	// Create the dictionary for returning
	Dictionary real_time_status;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, real_time_status, "[STEAM SERVER] Networking Sockets class not found when calling: getConnectionRealTimeStatus");
	SteamNetConnectionRealTimeStatus_t this_status;
	SteamNetConnectionRealTimeLaneStatus_t *lanes_array = new SteamNetConnectionRealTimeLaneStatus_t[lanes];
	int result = SteamNetworkingSockets()->GetConnectionRealTimeStatus((HSteamNetConnection)connection, &this_status, lanes, lanes_array);

	real_time_status["response"] = result;
	if (result == RESULT_OK) {
		Dictionary connection_status;
		if (get_status) {
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

		Array lanes_status;
		for (int i = 0; i < lanes; i++) {
			Dictionary lane_status;
			lane_status["pending_unreliable"] = lanes_array[i].m_cbPendingUnreliable;
			lane_status["pending_reliable"] = lanes_array[i].m_cbPendingReliable;
			lane_status["sent_unacknowledged_reliable"] = lanes_array[i].m_cbSentUnackedReliable;
			lane_status["queue_time"] = (uint64_t)lanes_array[i].m_usecQueueTime;
			lanes_status.append(lane_status);
		}
		real_time_status["lanes_status"] = lanes_status;
	}
	delete[] lanes_array;
	return real_time_status;
}

// Configure multiple outbound messages streams ("lanes") on a connection, and control head-of-line blocking between them.
// Messages within a given lane are always sent in the order they are queued, but messages from different lanes may be sent out of order.
// Each lane has its own message number sequence.  The first message sent on each lane will be assigned the number 1.
int SteamServer::configureConnectionLanes(uint32 connection, uint32 lanes, Array priorities, Array weights) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: configureConnectionLanes");
	int *lane_priorities = new int[lanes];
	for (uint32 i = 0; i < lanes; i++) {
		lane_priorities[i] = priorities[i];
	}

	uint16 *lane_weights = new uint16[lanes];
	for (uint32 i = 0; i < lanes; i++) {
		lane_weights[i] = weights[i];
	}
	int result = SteamNetworkingSockets()->ConfigureConnectionLanes((HSteamNetConnection)connection, lanes, lane_priorities, lane_weights);
	delete[] lane_priorities;
	delete[] lane_weights;
	return result;
}

// Certificate provision by the application. On Steam, we normally handle all this automatically and you will not need to use these advanced functions.
Dictionary SteamServer::getCertificateRequest() {
	Dictionary cert_information;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, cert_information, "[STEAM SERVER] Networking Sockets class not found when calling: getCertificateRequest");
	PoolByteArray certificate;
	certificate.resize(512);
	int cert_size = certificate.size();
	SteamNetworkingErrMsg error_message;
	if (SteamNetworkingSockets()->GetCertificateRequest(&cert_size, certificate.write().ptr(), error_message)) {
		certificate.resize(cert_size);
		cert_information["certificate"] = certificate;
		cert_information["error_message"] = error_message;
	}
	return cert_information;
}

// Set the certificate. The certificate blob should be the output of SteamDatagram_CreateCert.
Dictionary SteamServer::setCertificate(const PoolByteArray &certificate) {
	Dictionary certificate_data;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, certificate_data, "[STEAM SERVER] Networking Sockets class not found when calling: setCertificate");
	bool success = false;
	SteamNetworkingErrMsg error_message;

	success = SteamNetworkingSockets()->SetCertificate((void *)certificate.read().ptr(), certificate.size(), error_message);
	if (success) {
		certificate_data["response"] = success;
		certificate_data["error"] = error_message;
	}
	return certificate_data;
}

// Reset the identity associated with this instance. Any open connections are closed.  Any previous certificates, etc are discarded.
// You can pass a specific identity that you want to use, or you can pass NULL, in which case the identity will be invalid until you set it using SetCertificate.
// NOTE: This function is not actually supported on Steam!  It is included for use on other platforms where the active user can sign out and a new user can sign in.
void SteamServer::resetIdentity(uint64_t remote_steam_id) {
	ERR_FAIL_COND_MSG(SteamNetworkingSockets() == NULL, "[STEAM SERVER] Networking Sockets class not found when calling: resetIdentity");
	SteamNetworkingIdentity resetting_identity = getIdentityFromSteamID(remote_steam_id);
	SteamNetworkingSockets()->ResetIdentity(&resetting_identity);
}

// Invoke all callback functions queued for this interface. See k_ESteamNetworkingConfig_Callback_ConnectionStatusChanged, etc.
// You don't need to call this if you are using Steam's callback dispatch mechanism (SteamAPI_RunCallbacks and SteamGameserver_RunCallbacks).
void SteamServer::runNetworkingCallbacks() {
	ERR_FAIL_COND_MSG(SteamNetworkingSockets() == NULL, "[STEAM SERVER] Networking Sockets class not found when calling: runNetworkingCallbacks");
	SteamNetworkingSockets()->RunCallbacks();
}

// Begin asynchronous process of allocating a fake IPv4 address that other peers can use to contact us via P2P.
// IP addresses returned by this function are globally unique for a given appid.
// Returns false if a request was already in progress, true if a new request was started.
// A SteamNetworkingFakeIPResult_t will be posted when the request completes.
bool SteamServer::beginAsyncRequestFakeIP(int num_ports) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, false, "[STEAM SERVER] Networking Sockets class not found when calling: beginAsyncRequestFakeIP");
	return SteamNetworkingSockets()->BeginAsyncRequestFakeIP(num_ports);
}

// Return info about the FakeIP and port(s) that we have been assigned, if any.
// idxFirstPort is currently reserved and must be zero. Make sure and check SteamNetworkingFakeIPResult_t::m_eResult
Dictionary SteamServer::getFakeIP(int first_port) {
	Dictionary fake_ip;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, fake_ip, "[STEAM SERVER] Networking Sockets class not found when calling: getFakeIP");
	SteamNetworkingFakeIPResult_t fake_ip_result;
	SteamNetworkingSockets()->GetFakeIP(first_port, &fake_ip_result);
	
	fake_ip["result"] = fake_ip_result.m_eResult;
	fake_ip["identity_type"] = fake_ip_result.m_identity.m_eType;
	fake_ip["ip"] = getStringFromIP(fake_ip_result.m_unIP);
		
	PoolIntArray ports;
	ports.resize(SteamNetworkingFakeIPResult_t::k_nMaxReturnPorts);
	for (size_t i = 0; i < SteamNetworkingFakeIPResult_t::k_nMaxReturnPorts; i++) {
		ports.append(fake_ip_result.m_unPorts[i]);
	}
	fake_ip["ports"] = ports;
	return fake_ip;
}

// Create a listen socket that will listen for P2P connections sent to our FakeIP.
// A peer can initiate connections to this listen socket by calling ConnectByIPAddress.
uint32 SteamServer::createListenSocketP2PFakeIP(int fake_port, Dictionary config_options) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, 0, "[STEAM SERVER] Networking Sockets class not found when calling: createListenSocketP2PFakeIP");
	uint32 listen_socket = SteamNetworkingSockets()->CreateListenSocketP2PFakeIP(fake_port, config_options.size(), convert_config_options(config_options));
	return listen_socket;
}

// If the connection was initiated using the "FakeIP" system, then we we can get an IP address for the remote host.  If the remote host had a global FakeIP at the time the connection was established, this function will return that global IP.
// Otherwise, a FakeIP that is unique locally will be allocated from the local FakeIP address space, and that will be returned.
Dictionary SteamServer::getRemoteFakeIPForConnection(uint32 connection) {
	Dictionary this_fake_address;
	ERR_FAIL_COND_V_MSG(SteamNetworkingSockets() == NULL, this_fake_address, "[STEAM SERVER] Networking Sockets class not found when calling: getRemoteFakeIPForConnection");
	SteamNetworkingIPAddr fake_address;
	int result = SteamNetworkingSockets()->GetRemoteFakeIPForConnection((HSteamNetConnection)connection, &fake_address);
	
	this_fake_address["result"] = result;
	this_fake_address["ip_address"] = getStringFromSteamIP(fake_address);
	this_fake_address["port"] = fake_address.m_port;
	this_fake_address["ip_type"] = fake_address.GetFakeIPType();
	return this_fake_address;
}

// Get an interface that can be used like a UDP port to send/receive datagrams to a FakeIP address.
// This is intended to make it easy to port existing UDP-based code to take advantage of SDR.
// To create a "client" port (e.g. the equivalent of an ephemeral UDP port) pass -1.
void SteamServer::createFakeUDPPort(int fake_server_port_index) {
	ERR_FAIL_COND_MSG(SteamNetworkingSockets() == NULL, "[STEAM SERVER] Networking Sockets class not found when calling: createFakeUDPPort");
	SteamNetworkingSockets()->CreateFakeUDPPort(fake_server_port_index);
}


///// NETWORKING UTILS

// If you know that you are going to be using the relay network (for example, because you anticipate making P2P connections), call this to initialize the relay network. If you do not call this, the initialization will be delayed until the first time you use a feature that requires access to the relay network, which will delay that first access.
void SteamServer::initRelayNetworkAccess() {
	ERR_FAIL_COND_MSG(SteamNetworkingUtils() == NULL, "[STEAM SERVER] Networking Utils class not found when calling: initRelayNetworkAccess");
	SteamNetworkingUtils()->InitRelayNetworkAccess();
}

// Fetch current status of the relay network.  If you want more details, you can pass a non-NULL value.
NetworkingAvailability SteamServer::getRelayNetworkStatus() {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, NETWORKING_AVAILABILITY_UNKNOWN, "[STEAM SERVER] Networking Utils class not found when calling: getRelayNetworkStatus");
	return NetworkingAvailability(SteamNetworkingUtils()->GetRelayNetworkStatus(NULL));
}

// Return location info for the current host. Returns the approximate age of the data, in seconds, or -1 if no data is available.
Dictionary SteamServer::getLocalPingLocation() {
	Dictionary ping_location;
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, ping_location, "[STEAM SERVER] Networking Utils class not found when calling: getLocalPingLocation");
	SteamNetworkPingLocation_t location;
	float age = SteamNetworkingUtils()->GetLocalPingLocation(location);

	PoolByteArray data;
	data.resize(512);
	uint8_t *output_data = data.write().ptr();
	for (int j = 0; j < 512; j++) {
		output_data[j] = location.m_data[j];
	}
	ping_location["age"] = age;
	ping_location["location"] = data;
	return ping_location;
}

// Estimate the round-trip latency between two arbitrary locations, in milliseconds. This is a conservative estimate, based on routing through the relay network. For most basic relayed connections, this ping time will be pretty accurate, since it will be based on the route likely to be actually used.
int SteamServer::estimatePingTimeBetweenTwoLocations(PoolByteArray location1, PoolByteArray location2) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, 0, "[STEAM SERVER] Networking Utils class not found when calling: estimatePingTimeBetweenTwoLocations");
	SteamNetworkPingLocation_t ping_location1;
	SteamNetworkPingLocation_t ping_location2;
	uint8_t *input_location_1 = (uint8 *)location1.read().ptr();
	for (int j = 0; j < 512; j++) {
		ping_location1.m_data[j] = input_location_1[j];
	}

	uint8_t *input_location_2 = (uint8 *)location2.read().ptr();
	for (int j = 0; j < 512; j++) {
		ping_location2.m_data[j] = (uint8)input_location_2[j];
	}
	return SteamNetworkingUtils()->EstimatePingTimeBetweenTwoLocations(ping_location1, ping_location2);
}

// Same as EstimatePingTime, but assumes that one location is the local host. This is a bit faster, especially if you need to calculate a bunch of these in a loop to find the fastest one.
int SteamServer::estimatePingTimeFromLocalHost(PoolByteArray location) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, 0, "[STEAM SERVER] Networking Utils class not found when calling: estimatePingTimeFromLocalHost");
	SteamNetworkPingLocation_t ping_location;
	uint8_t *input_location = (uint8 *)location.read().ptr();
	for (int j = 0; j < 512; j++) {
		ping_location.m_data[j] = input_location[j];
	}
	return SteamNetworkingUtils()->EstimatePingTimeFromLocalHost(ping_location);
}

// Convert a ping location into a text format suitable for sending over the wire. The format is a compact and human readable. However, it is subject to change so please do not parse it yourself. Your buffer must be at least k_cchMaxSteamNetworkingPingLocationString bytes.
String SteamServer::convertPingLocationToString(PoolByteArray location) {
	String location_string = "";
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, location_string, "[STEAM SERVER] Networking Utils class not found when calling: convertPingLocationToString");
	SteamNetworkPingLocation_t ping_location;
	uint8_t *input_location = (uint8*)location.read().ptr();
	for (int j = 0; j < 512; j++) {
		ping_location.m_data[j] = input_location[j];
	}

	char buffer[512 + 1]{};
	SteamNetworkingUtils()->ConvertPingLocationToString(ping_location, buffer, k_cchMaxSteamNetworkingPingLocationString);
	location_string += buffer;
	return location_string;
}

// Parse back SteamNetworkPingLocation_t string. Returns false if we couldn't understand the string.
Dictionary SteamServer::parsePingLocationString(const String &location_string) {
	Dictionary parse_string;
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, parse_string, "[STEAM SERVER] Networking Utils class not found when calling: parsePingLocationString");
	SteamNetworkPingLocation_t result;
	bool success = SteamNetworkingUtils()->ParsePingLocationString(location_string.utf8().get_data(), result);
	
	PoolByteArray data;
	data.resize(512);
	uint8_t *output_data = data.write().ptr();
	for (int j = 0; j < 512; j++) {
		output_data[j] = result.m_data[j];
	}
	parse_string["success"] = success;
	parse_string["ping_location"] = data;
	return parse_string;
}

// Check if the ping data of sufficient recency is available, and if it's too old, start refreshing it.
bool SteamServer::checkPingDataUpToDate(float max_age_in_seconds) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, false, "[STEAM SERVER] Networking Utils class not found when calling: checkPingDataUpToDate");
	return SteamNetworkingUtils()->CheckPingDataUpToDate(max_age_in_seconds);
}

// Fetch ping time of best available relayed route from this host to the specified data center.
Dictionary SteamServer::getPingToDataCenter(uint32 pop_id) {
	Dictionary data_center_ping;
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, data_center_ping, "[STEAM SERVER] Networking Utils class not found when calling: getPingToDataCenter");
	SteamNetworkingPOPID via_relay_pop;
	int ping = SteamNetworkingUtils()->GetPingToDataCenter((SteamNetworkingPOPID)pop_id, &via_relay_pop);

	data_center_ping["pop_relay"] = via_relay_pop;
	data_center_ping["ping"] = ping;
	return data_center_ping;
}

// Get *direct* ping time to the relays at the point of presence.
int SteamServer::getDirectPingToPOP(uint32 pop_id) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, 0, "[STEAM SERVER] Networking Utils class not found when calling: getDirectPingToPOP");
	return SteamNetworkingUtils()->GetDirectPingToPOP((SteamNetworkingPOPID)pop_id);
}

// Get number of network points of presence in the config
int SteamServer::getPOPCount() {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, 0, "[STEAM SERVER] Networking Utils class not found when calling: getPOPCount");
	return SteamNetworkingUtils()->GetPOPCount();
}

// Get list of all POP IDs. Returns the number of entries that were filled into your list.
Array SteamServer::getPOPList() {
	Array pop_list;
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, pop_list, "[STEAM SERVER] Networking Utils class not found when calling: getPOPList");
	SteamNetworkingPOPID list[256];
	int pops = SteamNetworkingUtils()->GetPOPList(list, 256);
	
	for (int i = 0; i < pops; i++) {
		int pop_id = list[i];
		pop_list.append(pop_id);
	}
	return pop_list;
}

// Set a configuration value.
//bool SteamServer::setConfigValue(int setting, int scope_type, uint32_t connection_handle, int data_type, auto value) {
//	ERR_FAIL_COND_V_MSG(SteamGameServer() == NULL, false, "[STEAM SERVER] Networking Utils class not found when calling: setConfigValue");
//	return SteamNetworkingUtils()->SetConfigValue((ESteamNetworkingConfigValue)setting, (ESteamNetworkingConfigScope)scope_type, connection_handle, (ESteamNetworkingConfigDataType)data_type, value);
//}

// Get a configuration value.
Dictionary SteamServer::getConfigValue(NetworkingConfigValue config_value, NetworkingConfigScope scope_type, uint32_t connection_handle) {
	Dictionary config_info;
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, config_info, "[STEAM SERVER] Networking Utils class not found when calling: getConfigValue");
	ESteamNetworkingConfigDataType data_type;
	size_t buffer_size;
	PoolByteArray config_result;
	int result = SteamNetworkingUtils()->GetConfigValue((ESteamNetworkingConfigValue)config_value, (ESteamNetworkingConfigScope)scope_type, connection_handle, &data_type, &config_result, &buffer_size);
	
	config_info["result"] = result;
	config_info["type"] = data_type;
	config_info["value"] = config_result;
	config_info["buffer"] = (uint64_t)buffer_size;
	return config_info;
}

// Returns info about a configuration value.
Dictionary SteamServer::getConfigValueInfo(NetworkingConfigValue config_value) {
	Dictionary config_info;
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, config_info, "[STEAM SERVER] Networking Utils class not found when calling: getConfigValueInfo");
	ESteamNetworkingConfigDataType data_type;
	ESteamNetworkingConfigScope scope;
	if (SteamNetworkingUtils()->GetConfigValueInfo((ESteamNetworkingConfigValue)config_value, &data_type, &scope)) {
		config_info["type"] = data_type;
		config_info["scope"] = scope;
	}
	return config_info;
}

// The following functions are handy shortcuts for common use cases.
bool SteamServer::setGlobalConfigValueInt32(NetworkingConfigValue config, int32 value) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, false, "[STEAM SERVER] Networking Utils class not found when calling: setGlobalConfigValueInt32");
	return SteamNetworkingUtils()->SetGlobalConfigValueInt32((ESteamNetworkingConfigValue)config, value);
}

bool SteamServer::setGlobalConfigValueFloat(NetworkingConfigValue config, float value) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, false, "[STEAM SERVER] Networking Utils class not found when calling: setGlobalConfigValueFloat");
	return SteamNetworkingUtils()->SetGlobalConfigValueFloat((ESteamNetworkingConfigValue)config, value);
}

bool SteamServer::setGlobalConfigValueString(NetworkingConfigValue config, const String &value) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, false, "[STEAM SERVER] Networking Utils class not found when calling: setGlobalConfigValueString");
	return SteamNetworkingUtils()->SetGlobalConfigValueString((ESteamNetworkingConfigValue)config, value.utf8().get_data());
}

bool SteamServer::setConnectionConfigValueInt32(uint32 connection, NetworkingConfigValue config, int32 value) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, false, "[STEAM SERVER] Networking Utils class not found when calling: setConnectionConfigValueInt32");
	return SteamNetworkingUtils()->SetConnectionConfigValueInt32(connection, (ESteamNetworkingConfigValue)config, value);
}

bool SteamServer::setConnectionConfigValueFloat(uint32 connection, NetworkingConfigValue config, float value) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, false, "[STEAM SERVER] Networking Utils class not found when calling: setConnectionConfigValueFloat");
	return SteamNetworkingUtils()->SetConnectionConfigValueFloat(connection, (ESteamNetworkingConfigValue)config, value);
}

bool SteamServer::setConnectionConfigValueString(uint32 connection, NetworkingConfigValue config, const String &value) {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, false, "[STEAM SERVER] Networking Utils class not found when calling: setConnectionConfigValueString");
	return SteamNetworkingUtils()->SetConnectionConfigValueString(connection, (ESteamNetworkingConfigValue)config, value.utf8().get_data());
}

// A general purpose high resolution local timer with the following properties: Monotonicity is guaranteed. The initial value will be at least 24*3600*30*1e6, i.e. about 30 days worth of microseconds. In this way, the time_stamp value of 0 will always be at least "30 days ago". Also, negative numbers will never be returned. Wraparound / overflow is not a practical concern.
uint64_t SteamServer::getLocalTimestamp() {
	ERR_FAIL_COND_V_MSG(SteamNetworkingUtils() == NULL, 0, "[STEAM SERVER] Networking Utils class not found when calling: getLocalTimestamp");
	return SteamNetworkingUtils()->GetLocalTimestamp();
}


///// UGC

// Adds a dependency between the given item and the appid. This list of dependencies can be retrieved by calling GetAppDependencies.
// This is a soft-dependency that is displayed on the web. It is up to the application to determine whether the item can actually be used or not.
void SteamServer::addAppDependency(uint64_t published_file_id, uint32_t app_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: addAppDependency");
	SteamAPICall_t api_call = SteamUGC()->AddAppDependency((PublishedFileId_t)published_file_id, (AppId_t)app_id);
	callResultAddAppDependency.Set(api_call, this, &SteamServer::add_app_dependency_result);
}

bool SteamServer::addContentDescriptor(uint64_t update_handle, int descriptor_id) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: addContentDescriptor");
	return SteamUGC()->AddContentDescriptor((UGCUpdateHandle_t)update_handle, (EUGCContentDescriptorID)descriptor_id);
}

// Adds a workshop item as a dependency to the specified item. If the nParentPublishedFileID item is of type k_EWorkshopFileTypeCollection, than the nChildPublishedFileID is simply added to that collection.
// Otherwise, the dependency is a soft one that is displayed on the web and can be retrieved via the ISteamUGC API using a combination of the m_unNumChildren member variable of the SteamUGCDetails_t struct and GetQueryUGCChildren.
void SteamServer::addDependency(uint64_t published_file_id, uint64_t child_published_file_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: addDependency");
	SteamAPICall_t api_call = SteamUGC()->AddDependency((PublishedFileId_t)published_file_id, (PublishedFileId_t)child_published_file_id);
	callResultAddUGCDependency.Set(api_call, this, &SteamServer::add_ugc_dependency_result);
}

// Adds a excluded tag to a pending UGC Query. This will only return UGC without the specified tag.
bool SteamServer::addExcludedTag(uint64_t query_handle, const String &tag_name) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: addExcludedTag");
	return SteamUGC()->AddExcludedTag((UGCQueryHandle_t)query_handle, tag_name.utf8().get_data());
}

// Adds a key-value tag pair to an item. Keys can map to multiple different values (1-to-many relationship).
bool SteamServer::addItemKeyValueTag(uint64_t update_handle, const String &key, const String &value) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: addItemKeyValueTag");
	return SteamUGC()->AddItemKeyValueTag((UGCUpdateHandle_t)update_handle, key.utf8().get_data(), value.utf8().get_data());
}

// Adds an additional preview file for the item.
bool SteamServer::addItemPreviewFile(uint64_t query_handle, const String &preview_file, ItemPreviewType type) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: addItemPreviewFile");
	return SteamUGC()->AddItemPreviewFile((UGCQueryHandle_t)query_handle, preview_file.utf8().get_data(), (EItemPreviewType)type);
}

// Adds an additional video preview from YouTube for the item.
bool SteamServer::addItemPreviewVideo(uint64_t query_handle, const String &video_id) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: addItemPreviewVideo");
	return SteamUGC()->AddItemPreviewVideo((UGCQueryHandle_t)query_handle, video_id.utf8().get_data());
}

// Adds a workshop item to the users favorites list.
void SteamServer::addItemToFavorites(uint32_t app_id, uint64_t published_file_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: addItemToFavorites");
	AppId_t app = (uint32_t)app_id;
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	SteamAPICall_t api_call = SteamUGC()->AddItemToFavorites(app, file_id);
	callResultFavoriteItemListChanged.Set(api_call, this, &SteamServer::user_favorite_items_list_changed);
}

// Adds a required key-value tag to a pending UGC Query. This will only return workshop items that have a key = pKey and a value = pValue.
bool SteamServer::addRequiredKeyValueTag(uint64_t query_handle, const String &key, const String &value) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: addRequiredKeyValueTag");
	return SteamUGC()->AddRequiredKeyValueTag((UGCQueryHandle_t)query_handle, key.utf8().get_data(), value.utf8().get_data());
}

// Adds a required tag to a pending UGC Query. This will only return UGC with the specified tag.
bool SteamServer::addRequiredTag(uint64_t query_handle, const String &tag_name) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: addRequiredTag");
	return SteamUGC()->AddRequiredTag((UGCQueryHandle_t)query_handle, tag_name.utf8().get_data());
}

// Adds the requirement that the returned items from the pending UGC Query have at least one of the tags in the given set (logical "or"). For each tag group that is added, at least one tag from each group is required to be on the matching items.
bool SteamServer::addRequiredTagGroup(uint64_t query_handle, Array tag_array) {
	bool added_tag_group = false;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, added_tag_group, "[STEAM SERVER] UGC class not found when calling: addRequiredTagGroup");
	UGCQueryHandle_t handle = uint64(query_handle);
	std::vector<CharString> string_store(tag_array.size());
	std::vector<const char *> strings(tag_array.size());
	uint32 str_count = tag_array.size();
	for (uint32 i = 0; i < str_count; i++) {
		String str = tag_array[i];
		string_store[i] = str.utf8();
		strings[i] = string_store[i].get_data();
	}
	SteamParamStringArray_t tag;
	tag.m_nNumStrings = strings.size();
	tag.m_ppStrings = strings.data();
	added_tag_group = SteamUGC()->AddRequiredTagGroup(handle, &tag);
	return added_tag_group;
}

// Lets game servers set a specific workshop folder before issuing any UGC commands.
bool SteamServer::initWorkshopForGameServer(uint32_t workshop_depot_id, String folder) {
	bool initialized_workshop = false;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, initialized_workshop, "[STEAM SERVER] UGC class not found when calling: initWorkshopForGameServer");
	DepotId_t workshop = (uint32_t)workshop_depot_id;
	initialized_workshop = SteamUGC()->BInitWorkshopForGameServer(workshop, folder.utf8());
	return initialized_workshop;
}

// Creates a new workshop item with no content attached yet.
void SteamServer::createItem(uint32 app_id, WorkshopFileType file_type) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: createItem");
	SteamAPICall_t api_call = SteamUGC()->CreateItem((AppId_t)app_id, (EWorkshopFileType)file_type);
	callResultItemCreate.Set(api_call, this, &SteamServer::item_created);
}

// Query for all matching UGC. You can use this to list all of the available UGC for your app.
uint64_t SteamServer::createQueryAllUGCRequest(UGCQuery query_type, UGCMatchingUGCType matching_type, uint32_t creator_id, uint32_t consumer_id, uint32 page) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, 0, "[STEAM SERVER] UGC class not found when calling: createQueryAllUGCRequest");
	AppId_t creator = (uint32_t)creator_id;
	AppId_t consumer = (uint32_t)consumer_id;
	UGCQueryHandle_t handle = SteamUGC()->CreateQueryAllUGCRequest((EUGCQuery)query_type, (EUGCMatchingUGCType)matching_type, creator, consumer, page);
	return (uint64_t)handle;
}

// Query for the details of specific workshop items.
uint64_t SteamServer::createQueryUGCDetailsRequest(Array published_file_ids) {
	uint64_t this_handle = 0;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, this_handle, "[STEAM SERVER] UGC class not found when calling: createQueryUGCDetailsRequest");
	uint32 file_count = published_file_ids.size();
	if (file_count != 0) {
		PublishedFileId_t *file_ids = new PublishedFileId_t[file_count];
		for (uint32 i = 0; i < file_count; i++) {
			file_ids[i] = (uint64_t)published_file_ids[i];
		}
		UGCQueryHandle_t handle = SteamUGC()->CreateQueryUGCDetailsRequest(file_ids, file_count);
		delete[] file_ids;
		this_handle = (uint64_t)handle;
	}
	return this_handle;
}

// Query UGC associated with a user. You can use this to list the UGC the user is subscribed to amongst other things.
uint64_t SteamServer::createQueryUserUGCRequest(uint64_t steam_id, UserUGCList list_type, UGCMatchingUGCType matching_ugc_type, UserUGCListSortOrder sort_order, uint32_t creator_id, uint32_t consumer_id, uint32 page) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, 0, "[STEAM SERVER] UGC class not found when calling: createQueryUGCDetailsRequest");
	// Get tue universe ID from the Steam ID
	CSteamID user_id = (uint64)steam_id;
	AccountID_t account = (AccountID_t)user_id.ConvertToUint64();
	AppId_t creator = (int)creator_id;
	AppId_t consumer = (int)consumer_id;
	UGCQueryHandle_t handle = SteamUGC()->CreateQueryUserUGCRequest(account, (EUserUGCList)list_type, (EUGCMatchingUGCType)matching_ugc_type, (EUserUGCListSortOrder)sort_order, creator, consumer, page);
	return (uint64_t)handle;
}

// Deletes the item without prompting the user.
void SteamServer::deleteItem(uint64_t published_file_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: deleteItem");
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	SteamAPICall_t api_call = SteamUGC()->DeleteItem(file_id);
	callResultDeleteItem.Set(api_call, this, &SteamServer::item_deleted);
}

// Download new or update already installed item. If returns true, wait for DownloadItemResult_t. If item is already installed, then files on disk should not be used until callback received.
// If item is not subscribed to, it will be cached for some time. If bHighPriority is set, any other item download will be suspended and this item downloaded ASAP.
bool SteamServer::downloadItem(uint64_t published_file_id, bool high_priority) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: downloadItem");
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	return SteamUGC()->DownloadItem(file_id, high_priority);
}

// Returns any app dependencies that are associated with the given item.
void SteamServer::getAppDependencies(uint64_t published_file_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: getAppDependencies");
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	SteamAPICall_t api_call = SteamUGC()->GetAppDependencies(file_id);
	callResultGetAppDependencies.Set(api_call, this, &SteamServer::get_app_dependencies_result);
}

// Get info about a pending download of a workshop item that has k_EItemStateNeedsUpdate set.
Dictionary SteamServer::getItemDownloadInfo(uint64_t published_file_id) {
	Dictionary info;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, info, "[STEAM SERVER] UGC class not found when calling: getItemDownloadInfo");
	uint64 downloaded = 0;
	uint64 total = 0;
	info["ret"] = SteamUGC()->GetItemDownloadInfo((PublishedFileId_t)published_file_id, &downloaded, &total);
	if (info["ret"]) {
		info["downloaded"] = uint64_t(downloaded);
		info["total"] = uint64_t(total);
	}
	return info;
}

// Gets info about currently installed content on the disc for workshop items that have k_EItemStateInstalled set.
Dictionary SteamServer::getItemInstallInfo(uint64_t published_file_id) {
	Dictionary info;
	info["ret"] = false;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, info, "[STEAM SERVER] UGC class not found when calling: getItemInstallInfo");
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	uint64 size_on_disk;
	char folder[1024] = { 0 };
	uint32 time_stamp;
	info["ret"] = SteamUGC()->GetItemInstallInfo((PublishedFileId_t)file_id, &size_on_disk, folder, sizeof(folder), &time_stamp);
	if (info["ret"]) {
		info["size"] = (uint64_t)size_on_disk;
		info["folder"] = folder;
		info["timestamp"] = time_stamp;
	}
	return info;
}

// Gets the current state of a workshop item on this client.
uint32 SteamServer::getItemState(uint64_t published_file_id) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, 0, "[STEAM SERVER] UGC class not found when calling: getItemState");
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	return SteamUGC()->GetItemState(file_id);
}

// Gets the progress of an item update.
Dictionary SteamServer::getItemUpdateProgress(uint64_t update_handle) {
	Dictionary update_progress;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, update_progress, "[STEAM SERVER] UGC class not found when calling: getItemUpdateProgress");
	UGCUpdateHandle_t handle = (uint64_t)update_handle;
	uint64 processed = 0;
	uint64 total = 0;
	EItemUpdateStatus status = SteamUGC()->GetItemUpdateProgress(handle, &processed, &total);
	update_progress["status"] = status;
	update_progress["processed"] = uint64_t(processed);
	update_progress["total"] = uint64_t(total);
	return update_progress;
}

// Gets the total number of items the current user is subscribed to for the game or application.
uint32 SteamServer::getNumSubscribedItems() {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, 0, "[STEAM SERVER] UGC class not found when calling: getNumSubscribedItems");
	return SteamUGC()->GetNumSubscribedItems();
}

// Get the number of supported game versions for this UGC content.
uint32 SteamServer::getNumSupportedGameVersions(uint64_t query_handle, uint32 index) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, 0, "[STEAM SERVER] UGC class not found when calling: getNumSupportedGameVersions");
	return SteamUGC()->GetNumSupportedGameVersions((UGCQueryHandle_t)query_handle, index);
}

// Retrieve the details of an additional preview associated with an individual workshop item after receiving a querying UGC call result.
Dictionary SteamServer::getQueryUGCAdditionalPreview(uint64_t query_handle, uint32 index, uint32 preview_index) {
	Dictionary preview;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, preview, "[STEAM SERVER] UGC class not found when calling: getQueryUGCAdditionalPreview");
	char url_or_video_id[256 + 1]{};
	char original_filename[256 + 1]{};
	EItemPreviewType preview_type;
	bool success = SteamUGC()->GetQueryUGCAdditionalPreview((UGCQueryHandle_t)query_handle, index, preview_index, url_or_video_id, 256, original_filename, 256, &preview_type);
	if (success) {
		preview["success"] = success;
		preview["handle"] = (uint64_t)query_handle;
		preview["index"] = index;
		preview["preview"] = preview_index;
		preview["urlOrVideo"] = url_or_video_id;
		preview["filename"] = original_filename;
		preview["type"] = preview_type;
	}
	return preview;
}

// Retrieve the ids of any child items of an individual workshop item after receiving a querying UGC call result. These items can either be a part of a collection or some other dependency (see AddDependency).
Dictionary SteamServer::getQueryUGCChildren(uint64_t query_handle, uint32 index, uint32_t child_count) {
	Dictionary children;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, children, "[STEAM SERVER] UGC class not found when calling: getQueryUGCChildren");
	PoolVector<uint64_t> vec;
	vec.resize(child_count);
	bool success = SteamUGC()->GetQueryUGCChildren((UGCQueryHandle_t)query_handle, index, (PublishedFileId_t *)vec.write().ptr(), child_count);
	if (success) {
		Array godot_arr;
		godot_arr.resize(child_count);
		for (uint32_t i = 0; i < child_count; i++) {
			godot_arr[i] = vec[i];
		}

		children["success"] = success;
		children["handle"] = (uint64_t)query_handle;
		children["index"] = index;
		children["children"] = godot_arr;
	}
	return children;
}

Dictionary SteamServer::getQueryUGCContentDescriptors(uint64_t query_handle, uint32 index, uint32_t max_entries) {
	Dictionary descriptors;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, descriptors, "[STEAM SERVER] UGC class not found when calling: getQueryUGCContentDescriptors");
	PoolVector<uint64_t> vec;
	vec.resize(max_entries);
	uint32_t result = SteamUGC()->GetQueryUGCContentDescriptors((UGCQueryHandle_t)query_handle, index, (EUGCContentDescriptorID *)vec.write().ptr(), max_entries);
	Array descriptor_array;
	descriptor_array.resize(max_entries);
	for (uint32_t i = 0; i < max_entries; i++) {
		descriptor_array[i] = vec[i];
	}
	descriptors["result"] = result;
	descriptors["handle"] = (uint64_t)query_handle;
	descriptors["index"] = index;
	descriptors["descriptors"] = descriptor_array;
	return descriptors;
}

// Retrieve the details of a key-value tag associated with an individual workshop item after receiving a querying UGC call result.
Dictionary SteamServer::getQueryUGCKeyValueTag(uint64_t query_handle, uint32 index, uint32 key_value_tag_index) {
	Dictionary tag;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, tag, "[STEAM SERVER] UGC class not found when calling: getQueryUGCKeyValueTag");
	char key[256 + 1]{};
	char value[256 + 1]{};
	bool success = SteamUGC()->GetQueryUGCKeyValueTag((UGCQueryHandle_t)query_handle, index, key_value_tag_index, key, 256, value, 256);
	if (success) {
		tag["success"] = success;
		tag["handle"] = (uint64_t)query_handle;
		tag["index"] = index;
		tag["tag"] = key_value_tag_index;
		tag["key"] = key;
		tag["value"] = value;
	}
	return tag;
}

// Retrieve the developer set metadata of an individual workshop item after receiving a querying UGC call result.
String SteamServer::getQueryUGCMetadata(uint64_t query_handle, uint32 index) {
	String query_ugc_metadata = "";
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, query_ugc_metadata, "[STEAM SERVER] UGC class not found when calling: getQueryUGCMetadata");
	char ugc_metadata[5000 + 1]{};
	bool success = SteamUGC()->GetQueryUGCMetadata((UGCQueryHandle_t)query_handle, index, ugc_metadata, 5000);
	if (success) {
		query_ugc_metadata = ugc_metadata;
	}
	return query_ugc_metadata;
}

// Retrieve the number of additional previews of an individual workshop item after receiving a querying UGC call result.
uint32 SteamServer::getQueryUGCNumAdditionalPreviews(uint64_t query_handle, uint32 index) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, 0, "[STEAM SERVER] UGC class not found when calling: getQueryUGCNumAdditionalPreviews");
	return SteamUGC()->GetQueryUGCNumAdditionalPreviews((UGCQueryHandle_t)query_handle, index);
}

// Retrieve the number of key-value tags of an individual workshop item after receiving a querying UGC call result.
uint32 SteamServer::getQueryUGCNumKeyValueTags(uint64_t query_handle, uint32 index) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, 0, "[STEAM SERVER] UGC class not found when calling: getQueryUGCNumKeyValueTags");
	return SteamUGC()->GetQueryUGCNumKeyValueTags((UGCQueryHandle_t)query_handle, index);
}

// Retrieve the number of tags for an individual workshop item after receiving a querying UGC call result. You should call this in a loop to get the details of all the workshop items returned.
uint32 SteamServer::getQueryUGCNumTags(uint64_t query_handle, uint32 index) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, 0, "[STEAM SERVER] UGC class not found when calling: getQueryUGCNumTags");
	return SteamUGC()->GetQueryUGCNumTags((UGCQueryHandle_t)query_handle, index);
}

// Retrieve the URL to the preview image of an individual workshop item after receiving a querying UGC call result.
String SteamServer::getQueryUGCPreviewURL(uint64_t query_handle, uint32 index) {
	String query_ugc_preview_url = "";
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, query_ugc_preview_url, "[STEAM SERVER] UGC class not found when calling: getQueryUGCPreviewURL");
	char url[256 + 1]{};
	bool success = SteamUGC()->GetQueryUGCPreviewURL((UGCQueryHandle_t)query_handle, index, url, 256);
	if (success) {
		query_ugc_preview_url = url;
	}
	return query_ugc_preview_url;
}

// Retrieve the details of an individual workshop item after receiving a querying UGC call result.
Dictionary SteamServer::getQueryUGCResult(uint64_t query_handle, uint32 index) {
	Dictionary ugc_result;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, ugc_result, "[STEAM SERVER] UGC class not found when calling: getQueryUGCResult");
	SteamUGCDetails_t query_details;
	bool success = SteamUGC()->GetQueryUGCResult((UGCQueryHandle_t)query_handle, index, &query_details);
	if (success) {
		ugc_result["result"] = (uint64_t)query_details.m_eResult;
		ugc_result["file_id"] = (uint64_t)query_details.m_nPublishedFileId;
		ugc_result["file_type"] = (uint64_t)query_details.m_eFileType;
		ugc_result["creator_app_id"] = (uint32_t)query_details.m_nCreatorAppID;
		ugc_result["consumer_app_id"] = (uint32_t)query_details.m_nConsumerAppID;
		ugc_result["title"] = String::utf8(query_details.m_rgchTitle);
		ugc_result["description"] = String::utf8(query_details.m_rgchDescription);
		ugc_result["steam_id_owner"] = (uint64_t)query_details.m_ulSteamIDOwner;
		ugc_result["time_created"] = query_details.m_rtimeCreated;
		ugc_result["time_updated"] = query_details.m_rtimeUpdated;
		ugc_result["time_added_to_user_list"] = query_details.m_rtimeAddedToUserList;
		ugc_result["visibility"] = (uint64_t)query_details.m_eVisibility;
		ugc_result["banned"] = query_details.m_bBanned;
		ugc_result["accepted_for_use"] = query_details.m_bAcceptedForUse;
		ugc_result["tags_truncated"] = query_details.m_bTagsTruncated;
		ugc_result["tags"] = query_details.m_rgchTags;
		ugc_result["handle_file"] = (uint64_t)query_details.m_hFile;
		ugc_result["handle_preview_file"] = (uint64_t)query_details.m_hPreviewFile;
		ugc_result["file_name"] = query_details.m_pchFileName;
		ugc_result["file_size"] = query_details.m_nFileSize;
		ugc_result["preview_file_size"] = query_details.m_nPreviewFileSize;
		ugc_result["url"] = query_details.m_rgchURL;
		ugc_result["votes_up"] = query_details.m_unVotesUp;
		ugc_result["votes_down"] = query_details.m_unVotesDown;
		ugc_result["score"] = query_details.m_flScore;
		ugc_result["num_children"] = query_details.m_unNumChildren;
		ugc_result["total_files_size"] = (uint64_t)query_details.m_ulTotalFilesSize;
	}
	return ugc_result;
}

// Retrieve various statistics of an individual workshop item after receiving a querying UGC call result.
Dictionary SteamServer::getQueryUGCStatistic(uint64_t query_handle, uint32 index, ItemStatistic stat_type) {
	Dictionary ugc_stat;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, ugc_stat, "[STEAM SERVER] UGC class not found when calling: getQueryUGCStatistic");
	uint64 value = 0;
	bool success = SteamUGC()->GetQueryUGCStatistic((UGCQueryHandle_t)query_handle, index, (EItemStatistic)stat_type, &value);
	if (success) {
		ugc_stat["success"] = success;
		ugc_stat["handle"] = (uint64_t)query_handle;
		ugc_stat["index"] = index;
		ugc_stat["type"] = stat_type;
		ugc_stat["value"] = (uint64_t)value;
	}
	return ugc_stat;
}

// Retrieve the "nth" tag associated with an individual workshop item after receiving a querying UGC call result.
// You should call this in a loop to get the details of all the workshop items returned.
String SteamServer::getQueryUGCTag(uint64_t query_handle, uint32 index, uint32 tag_index) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, "", "[STEAM SERVER] UGC class not found when calling: getQueryUGCTag");
	char tag[64 + 1]{};
	SteamUGC()->GetQueryUGCTag((UGCQueryHandle_t)query_handle, index, tag_index, tag, 64);
	return tag;
}

// Retrieve the "nth" display string (usually localized) for a tag, which is associated with an individual workshop item after receiving a querying UGC call result.
// You should call this in a loop to get the details of all the workshop items returned.
String SteamServer::getQueryUGCTagDisplayName(uint64_t query_handle, uint32 index, uint32 tag_index) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, "", "[STEAM SERVER] UGC class not found when calling: getQueryUGCTagDisplayName");
	char tag[256 + 1]{};
	SteamUGC()->GetQueryUGCTagDisplayName((UGCQueryHandle_t)query_handle, index, tag_index, tag, 256);
	return tag;
}

// Gets a list of all of the items the current user is subscribed to for the current game.
Array SteamServer::getSubscribedItems() {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, Array(), "[STEAM SERVER] UGC class not found when calling: getSubscribedItems");
	Array subscribed;
	uint32 num_items = SteamUGC()->GetNumSubscribedItems();
	PublishedFileId_t *items = new PublishedFileId_t[num_items];
	uint32 item_list = SteamUGC()->GetSubscribedItems(items, num_items);
	for (uint32 i = 0; i < item_list; i++) {
		subscribed.append((uint64_t)items[i]);
	}
	delete[] items;
	return subscribed;
}

// Some items can specify that they have a version that is valid for a range of game versions (Steam branch).
Dictionary SteamServer::getSupportedGameVersionData(uint64_t query_handle, uint32 index, uint32 version_index) {
	Dictionary supported_version;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, supported_version, "[STEAM SERVER] UGC class not found when calling: getSupportedGameVersionData");
	char branch_min[STEAM_BUFFER_SIZE];
	char branch_max[STEAM_BUFFER_SIZE];
	uint32 branch_size = 0;
	if (SteamUGC()->GetSupportedGameVersionData((UGCQueryHandle_t)query_handle, index, version_index, branch_min, branch_max, branch_size)) {
		supported_version["min"] = branch_min;
		supported_version["max"] = branch_max;
		supported_version["size"] = branch_size;
	}
	return supported_version;
}

// Return the user's community content descriptor preferences
// Information is unclear how this actually works so here goes nothing!
Array SteamServer::getUserContentDescriptorPreferences(uint32 max_entries) {
	Array descriptors;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, descriptors, "[STEAM SERVER] UGC class not found when calling: getUserContentDescriptorPreferences");
	EUGCContentDescriptorID *descriptor_list = new EUGCContentDescriptorID[max_entries];
	uint32 num_descriptors = SteamUGC()->GetUserContentDescriptorPreferences(descriptor_list, max_entries);
	for (uint32 i = 0; i < num_descriptors; i++) {
		descriptors.append(descriptor_list[i]);
	}
	return descriptors;
}

// Gets the users vote status on a workshop item.
void SteamServer::getUserItemVote(uint64_t published_file_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: getUserItemVote");	
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	SteamAPICall_t api_call = SteamUGC()->GetUserItemVote(file_id);
	callResultGetUserItemVote.Set(api_call, this, &SteamServer::get_item_vote_result);
}

// Retrieve information related to the user's acceptance or not of the app's specific Workshop EULA.
void SteamServer::getWorkshopEULAStatus() {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: subscribeItem");
	SteamAPICall_t api_call = SteamUGC()->GetWorkshopEULAStatus();
	callResultWorkshopEULAStatus.Set(api_call, this, &SteamServer::workshop_eula_status);
}

// Releases a UGC query handle when you are done with it to free up memory.
bool SteamServer::releaseQueryUGCRequest(uint64_t query_handle) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: releaseQueryUGCRequest");
	return SteamUGC()->ReleaseQueryUGCRequest((UGCQueryHandle_t)query_handle);
}

// Removes the dependency between the given item and the appid. This list of dependencies can be retrieved by calling GetAppDependencies.
void SteamServer::removeAppDependency(uint64_t published_file_id, uint32_t app_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: removeAppDependency");	
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	AppId_t app = (uint32_t)app_id;
	SteamAPICall_t api_call = SteamUGC()->RemoveAppDependency(file_id, app);
	callResultRemoveAppDependency.Set(api_call, this, &SteamServer::remove_app_dependency_result);
}

bool SteamServer::removeContentDescriptor(uint64_t update_handle, int descriptor_id) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: removeContentDescriptor");
	return SteamUGC()->RemoveContentDescriptor((UGCUpdateHandle_t)update_handle, (EUGCContentDescriptorID)descriptor_id);
}

// Removes a workshop item as a dependency from the specified item.
void SteamServer::removeDependency(uint64_t published_file_id, uint64_t child_published_file_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: removeDependency");	
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	PublishedFileId_t child_id = (uint64_t)child_published_file_id;
	SteamAPICall_t api_call = SteamUGC()->RemoveDependency(file_id, child_id);
	callResultRemoveUGCDependency.Set(api_call, this, &SteamServer::remove_ugc_dependency_result);
}

// Removes a workshop item from the users favorites list.
void SteamServer::removeItemFromFavorites(uint32_t app_id, uint64_t published_file_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: removeItemFromFavorites");	
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	AppId_t app = (uint32_t)app_id;
	SteamAPICall_t api_call = SteamUGC()->RemoveItemFromFavorites(app, file_id);
	callResultFavoriteItemListChanged.Set(api_call, this, &SteamServer::user_favorite_items_list_changed);
}

// Removes an existing key value tag from an item.
bool SteamServer::removeItemKeyValueTags(uint64_t update_handle, const String &key) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: removeItemKeyValueTags");
	return SteamUGC()->RemoveItemKeyValueTags((UGCUpdateHandle_t)update_handle, key.utf8().get_data());
}

// Removes an existing preview from an item.
bool SteamServer::removeItemPreview(uint64_t update_handle, uint32 index) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: removeItemPreview");
	return SteamUGC()->RemoveItemPreview((UGCUpdateHandle_t)update_handle, index);
}

// Send a UGC query to Steam.
void SteamServer::sendQueryUGCRequest(uint64_t update_handle) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: sendQueryUGCRequest");	
	SteamAPICall_t api_call = SteamUGC()->SendQueryUGCRequest((UGCUpdateHandle_t)update_handle);
	callResultUGCQueryCompleted.Set(api_call, this, &SteamServer::ugc_query_completed);
}

// Admin queries return hidden items.
bool SteamServer::setAdminQuery(uint64_t update_handle, bool admin_query) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setAdminQuery");
	return SteamUGC()->SetAdminQuery((UGCUpdateHandle_t)update_handle, admin_query);
}

// Sets whether results will be returned from the cache for the specific period of time on a pending UGC Query.
bool SteamServer::setAllowCachedResponse(uint64_t update_handle, uint32 max_age_seconds) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setAllowCachedResponse");
	return SteamUGC()->SetAllowCachedResponse((UGCUpdateHandle_t)update_handle, max_age_seconds);
}

// Sets to only return items that have a specific filename on a pending UGC Query.
bool SteamServer::setCloudFileNameFilter(uint64_t update_handle, const String &match_cloud_filename) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setCloudFileNameFilter");
	return SteamUGC()->SetCloudFileNameFilter((UGCUpdateHandle_t)update_handle, match_cloud_filename.utf8().get_data());
}

// Sets the folder that will be stored as the content for an item.
bool SteamServer::setItemContent(uint64_t update_handle, const String &content_folder) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setItemContent");
	return SteamUGC()->SetItemContent((UGCUpdateHandle_t)update_handle, content_folder.utf8().get_data());
}

// Sets a new description for an item.
bool SteamServer::setItemDescription(uint64_t update_handle, const String &description) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setItemDescription");
	if ((uint32_t)description.length() > (uint32_t)k_cchPublishedDocumentDescriptionMax) {
		printf("Description cannot have more than %d ASCII characters. Description not set.", k_cchPublishedDocumentDescriptionMax);
		return false;
	}
	return SteamUGC()->SetItemDescription((UGCUpdateHandle_t)update_handle, description.utf8().get_data());
}

// Sets arbitrary metadata for an item. This metadata can be returned from queries without having to download and install the actual content.
bool SteamServer::setItemMetadata(uint64_t update_handle, const String &ugc_metadata) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setItemMetadata");
	if (ugc_metadata.utf8().length() > 5000) {
		printf("Metadata cannot be more than %d bytes. Metadata not set.", 5000);
	}
	return SteamUGC()->SetItemMetadata((UGCUpdateHandle_t)update_handle, ugc_metadata.utf8().get_data());
}

// Sets the primary preview image for the item.
bool SteamServer::setItemPreview(uint64_t update_handle, const String &preview_file) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setItemPreview");
	return SteamUGC()->SetItemPreview((UGCUpdateHandle_t)update_handle, preview_file.utf8().get_data());
}

// Sets arbitrary developer specified tags on an item.
bool SteamServer::setItemTags(uint64_t update_handle, Array tag_array, bool allow_admin_tags) {
	bool tags_set = false;
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setItemTags");
	std::vector<CharString> string_store(tag_array.size());
	std::vector<const char *> strings(tag_array.size());
	uint32 str_count = tag_array.size();
	for (uint32 i = 0; i < str_count; i++) {
		String str = tag_array[i];
		string_store[i] = str.utf8();
		strings[i] = string_store[i].get_data();
	}
	SteamParamStringArray_t tag;
	tag.m_nNumStrings = strings.size();
	tag.m_ppStrings = strings.data();
	tags_set = SteamUGC()->SetItemTags((UGCUpdateHandle_t)update_handle, &tag, allow_admin_tags);
	return tags_set;
}

// Sets a new title for an item.
bool SteamServer::setItemTitle(uint64_t update_handle, const String &title) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setItemTitle");
	if (title.length() > 255) {
		printf("Title cannot have more than %d ASCII characters. Title not set.", 255);
		return false;
	}
	return SteamUGC()->SetItemTitle((UGCUpdateHandle_t)update_handle, title.utf8().get_data());
}

// Sets the language of the title and description that will be set in this item update.
bool SteamServer::setItemUpdateLanguage(uint64_t update_handle, const String &language) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setItemUpdateLanguage");
	return SteamUGC()->SetItemUpdateLanguage((UGCUpdateHandle_t)update_handle, language.utf8().get_data());
}

// Sets the visibility of an item.
bool SteamServer::setItemVisibility(uint64_t update_handle, RemoteStoragePublishedFileVisibility visibility) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setItemVisibility");
	return SteamUGC()->SetItemVisibility((UGCUpdateHandle_t)update_handle, (ERemoteStoragePublishedFileVisibility)visibility);
}

// Sets the language to return the title and description in for the items on a pending UGC Query.
bool SteamServer::setLanguage(uint64_t query_handle, const String &language) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setLanguage");
	return SteamUGC()->SetLanguage((UGCQueryHandle_t)query_handle, language.utf8().get_data());
}

// Sets whether workshop items will be returned if they have one or more matching tag, or if all tags need to match on a pending UGC Query.
bool SteamServer::setMatchAnyTag(uint64_t query_handle, bool match_any_tag) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setMatchAnyTag");
	return SteamUGC()->SetMatchAnyTag((UGCQueryHandle_t)query_handle, match_any_tag);
}

// Sets whether the order of the results will be updated based on the rank of items over a number of days on a pending UGC Query.
bool SteamServer::setRankedByTrendDays(uint64_t query_handle, uint32 days) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setRankedByTrendDays");
	return SteamUGC()->SetRankedByTrendDays((UGCQueryHandle_t)query_handle, days);
}

// An empty string for either parameter means that it will match any version on that end of the range. This will only be applied
// if the actual content has been changed.
bool SteamServer::setRequiredGameVersions(uint64_t query_handle, String game_branch_min, String game_branch_max) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setRequiredGameVersions");
	return SteamUGC()->SetRequiredGameVersions((UGCQueryHandle_t)query_handle, game_branch_min.utf8().get_data(), game_branch_max.utf8().get_data());
}

// Sets whether to return any additional images/videos attached to the items on a pending UGC Query.
bool SteamServer::setReturnAdditionalPreviews(uint64_t query_handle, bool return_additional_previews) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setReturnAdditionalPreviews");
	return SteamUGC()->SetReturnAdditionalPreviews((UGCQueryHandle_t)query_handle, return_additional_previews);
}

// Sets whether to return the IDs of the child items of the items on a pending UGC Query.
bool SteamServer::setReturnChildren(uint64_t query_handle, bool return_children) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setReturnChildren");
	return SteamUGC()->SetReturnChildren((UGCQueryHandle_t)query_handle, return_children);
}

// Sets whether to return any key-value tags for the items on a pending UGC Query.
bool SteamServer::setReturnKeyValueTags(uint64_t query_handle, bool return_key_value_tags) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setReturnKeyValueTags");
	return SteamUGC()->SetReturnKeyValueTags((UGCQueryHandle_t)query_handle, return_key_value_tags);
}

// Sets whether to return the full description for the items on a pending UGC Query.
bool SteamServer::setReturnLongDescription(uint64_t query_handle, bool return_long_description) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setReturnLongDescription");
	return SteamUGC()->SetReturnLongDescription((UGCQueryHandle_t)query_handle, return_long_description);
}

// Sets whether to return the developer specified metadata for the items on a pending UGC Query.
bool SteamServer::setReturnMetadata(uint64_t query_handle, bool return_metadata) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setReturnMetadata");
	return SteamUGC()->SetReturnMetadata((UGCQueryHandle_t)query_handle, return_metadata);
}

// Sets whether to only return IDs instead of all the details on a pending UGC Query.
bool SteamServer::setReturnOnlyIDs(uint64_t query_handle, bool return_only_ids) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setReturnOnlyIDs");
	return SteamUGC()->SetReturnOnlyIDs((UGCQueryHandle_t)query_handle, return_only_ids);
}

// Sets whether to return the the playtime stats on a pending UGC Query.
bool SteamServer::setReturnPlaytimeStats(uint64_t query_handle, uint32 days) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setReturnPlaytimeStats");
	return SteamUGC()->SetReturnPlaytimeStats((UGCQueryHandle_t)query_handle, days);
}

// Sets whether to only return the the total number of matching items on a pending UGC Query.
bool SteamServer::setReturnTotalOnly(uint64_t query_handle, bool return_total_only) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setReturnTotalOnly");
	return SteamUGC()->SetReturnTotalOnly((UGCQueryHandle_t)query_handle, return_total_only);
}

// Sets a string to that items need to match in either the title or the description on a pending UGC Query.
bool SteamServer::setSearchText(uint64_t query_handle, const String &search_text) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setSearchText");
	return SteamUGC()->SetSearchText((UGCQueryHandle_t)query_handle, search_text.utf8().get_data());
}

// Set the time range this item was created.
bool SteamServer::setTimeCreatedDateRange(uint64_t update_handle, uint32 start, uint32 end) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setTimeCreatedDateRange");
	return SteamUGC()->SetTimeCreatedDateRange((UGCUpdateHandle_t)update_handle, start, end);
}

// Set the time range this item was updated.
bool SteamServer::setTimeUpdatedDateRange(uint64_t update_handle, uint32 start, uint32 end) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: setTimeUpdatedDateRange");
	return SteamUGC()->SetTimeUpdatedDateRange((UGCUpdateHandle_t)update_handle, start, end);
}

// Allows the user to rate a workshop item up or down.
void SteamServer::setUserItemVote(uint64_t published_file_id, bool vote_up) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: setUserItemVote");
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	SteamAPICall_t api_call = SteamUGC()->SetUserItemVote(file_id, vote_up);
	callResultSetUserItemVote.Set(api_call, this, &SteamServer::set_user_item_vote);
}

// Show the app's latest Workshop EULA to the user in an overlay window, where they can accept it or not.
bool SteamServer::showWorkshopEULA() {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: showWorkshopEULA");
	return SteamUGC()->ShowWorkshopEULA();
}

// Starts the item update process.
uint64_t SteamServer::startItemUpdate(uint32_t app_id, uint64_t published_file_id) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, 0, "[STEAM SERVER] UGC class not found when calling: startItemUpdate");
	AppId_t app = (uint32_t)app_id;
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	return SteamUGC()->StartItemUpdate(app, file_id);
}

// Start tracking playtime on a set of workshop items.
void SteamServer::startPlaytimeTracking(Array published_file_ids) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: startPlaytimeTracking");
	uint32 file_count = published_file_ids.size();
	if (file_count > 0) {
		PublishedFileId_t *file_ids = new PublishedFileId_t[file_count];
		for (uint32 i = 0; i < file_count; i++) {
			file_ids[i] = (uint64_t)published_file_ids[i];
		}
		SteamAPICall_t api_call = SteamUGC()->StartPlaytimeTracking(file_ids, file_count);
		callResultStartPlaytimeTracking.Set(api_call, this, &SteamServer::start_playtime_tracking);
		delete[] file_ids;
	}
}

// Stop tracking playtime on a set of workshop items.
void SteamServer::stopPlaytimeTracking(Array published_file_ids) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: stopPlaytimeTracking");
	uint32 file_count = published_file_ids.size();
	if (file_count > 0) {
		PublishedFileId_t *file_ids = new PublishedFileId_t[file_count];
		Array files;
		for (uint32 i = 0; i < file_count; i++) {
			file_ids[i] = (uint64_t)published_file_ids[i];
		}
		SteamAPICall_t api_call = SteamUGC()->StopPlaytimeTracking(file_ids, file_count);
		callResultStopPlaytimeTracking.Set(api_call, this, &SteamServer::stop_playtime_tracking);
		delete[] file_ids;
	}
}

// Stop tracking playtime of all workshop items.
void SteamServer::stopPlaytimeTrackingForAllItems() {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: stopPlaytimeTrackingForAllItems");
	SteamAPICall_t api_call = SteamUGC()->StopPlaytimeTrackingForAllItems();
	callResultStopPlaytimeTracking.Set(api_call, this, &SteamServer::stop_playtime_tracking);
}


// Uploads the changes made to an item to the Steam Workshop; to be called after setting your changes.
void SteamServer::submitItemUpdate(uint64_t update_handle, const String &change_note) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: submitItemUpdate");
	SteamAPICall_t api_call;
	if (change_note.length() == 0) {
		api_call = SteamUGC()->SubmitItemUpdate((UGCUpdateHandle_t)update_handle, NULL);
	}
	else {
		api_call = SteamUGC()->SubmitItemUpdate((UGCUpdateHandle_t)update_handle, change_note.utf8().get_data());
	}
	callResultItemUpdate.Set(api_call, this, &SteamServer::item_updated);
}

// Subscribe to a workshop item. It will be downloaded and installed as soon as possible.
void SteamServer::subscribeItem(uint64_t published_file_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: subscribeItem");
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	SteamAPICall_t api_call = SteamUGC()->SubscribeItem(file_id);
	callResultSubscribeItem.Set(api_call, this, &SteamServer::subscribe_item);
}

// SuspendDownloads( true ) will suspend all workshop downloads until SuspendDownloads( false ) is called or the game ends.
void SteamServer::suspendDownloads(bool suspend) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: suspendDownloads");
	SteamUGC()->SuspendDownloads(suspend);
}

// Unsubscribe from a workshop item. This will result in the item being removed after the game quits.
void SteamServer::unsubscribeItem(uint64_t published_file_id) {
	ERR_FAIL_COND_MSG(SteamUGC() == NULL, "[STEAM SERVER] UGC class not found when calling: unsubscribeItem");
	PublishedFileId_t file_id = (uint64_t)published_file_id;
	SteamAPICall_t api_call = SteamUGC()->UnsubscribeItem(file_id);
	callResultUnsubscribeItem.Set(api_call, this, &SteamServer::unsubscribe_item);
}

// Updates an existing additional preview file for the item.
bool SteamServer::updateItemPreviewFile(uint64_t update_handle, uint32 index, const String &preview_file) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: updateItemPreviewFile");
	return SteamUGC()->UpdateItemPreviewFile((UGCUpdateHandle_t)update_handle, index, preview_file.utf8().get_data());
}

// Updates an additional video preview from YouTube for the item.
bool SteamServer::updateItemPreviewVideo(uint64_t update_handle, uint32 index, const String &video_id) {
	ERR_FAIL_COND_V_MSG(SteamUGC() == NULL, false, "[STEAM SERVER] UGC class not found when calling: updateItemPreviewVideo");
	return SteamUGC()->UpdateItemPreviewVideo((UGCUpdateHandle_t)update_handle, index, video_id.utf8().get_data());
}


///// SIGNALS / CALLBACKS

///// GAME SERVER

// Called when a connection attempt has failed. This will occur periodically if the Steam client is not connected, and has failed when retrying to establish a connection.
void SteamServer::server_connect_failure(SteamServerConnectFailure_t *server_data) {
	int result = server_data->m_eResult;
	bool retrying = server_data->m_bStillRetrying;
	emit_signal("server_connect_failure", result, retrying);
}

// Server has connected to the Steam back-end; server_data has no fields.
void SteamServer::server_connected(SteamServersConnected_t *server_data) {
	emit_signal("server_connected");
}

// Called if the client has lost connection to the Steam servers. Real-time services will be disabled until a matching SteamServersConnected_t has been posted.
void SteamServer::server_disconnected(SteamServersDisconnected_t *server_data) {
	int result = server_data->m_eResult;
	emit_signal("server_disconnected", result);
}

// Client has been approved to connect to this game server.
void SteamServer::client_approved(GSClientApprove_t *client_data) {
	uint64_t steam_id = client_data->m_SteamID.ConvertToUint64();
	uint64_t owner_id = client_data->m_OwnerSteamID.ConvertToUint64();
	emit_signal("client_approved", steam_id, owner_id);
}

// Client has been denied to connection to this game server.
void SteamServer::client_denied(GSClientDeny_t *client_data) {
	uint64_t steam_id = client_data->m_SteamID.ConvertToUint64();
	DenyReason reason = (DenyReason)client_data->m_eDenyReason;
	emit_signal("client_denied", steam_id, reason);
}

// Request the game server should kick the user.
void SteamServer::client_kick(GSClientKick_t *client_data) {
	uint64_t steam_id = client_data->m_SteamID.ConvertToUint64();
	DenyReason reason = (DenyReason)client_data->m_eDenyReason;
	emit_signal("client_kick", steam_id, reason);
}

// Received when the game server requests to be displayed as secure (VAC protected).
// m_bSecure is true if the game server should display itself as secure to users, false otherwise.
void SteamServer::policy_response(GSPolicyResponse_t *policy_data) {
	uint8 secure = policy_data->m_bSecure;
	emit_signal("policy_response", secure);
}

// Sent as a reply to RequestUserGroupStatus().
void SteamServer::client_group_status(GSClientGroupStatus_t *client_data) {
	uint64_t steam_id = client_data->m_SteamIDUser.ConvertToUint64();
	uint64_t group_id = client_data->m_SteamIDGroup.ConvertToUint64();
	bool member = client_data->m_bMember;
	bool officer = client_data->m_bOfficer;
	emit_signal("client_group_status", steam_id, group_id, member, officer);
}

// Sent as a reply to AssociateWithClan().
void SteamServer::associate_clan(AssociateWithClanResult_t *clan_data) {
	Result result = (Result)clan_data->m_eResult;
	emit_signal("associate_clan", result);
}

// Sent as a reply to ComputeNewPlayerCompatibility().
void SteamServer::player_compat(ComputeNewPlayerCompatibilityResult_t *player_data) {
	int result = player_data->m_eResult;
	int players_dont_like_candidate = player_data->m_cPlayersThatDontLikeCandidate;
	int players_candidate_doesnt_like = player_data->m_cPlayersThatCandidateDoesntLike;
	int clan_players_dont_like_candidate = player_data->m_cClanPlayersThatDontLikeCandidate;
	uint64_t steam_id = player_data->m_SteamIDCandidate.ConvertToUint64();
	emit_signal("player_compat", result, players_dont_like_candidate, players_candidate_doesnt_like, clan_players_dont_like_candidate, steam_id);
}


///// GAME SERVER STATS

// Result of a request to store the user stats.
void SteamServer::stats_stored(GSStatsStored_t *call_data) {
	EResult result = call_data->m_eResult;
	uint64_t steam_id = call_data->m_steamIDUser.ConvertToUint64();
	emit_signal("stats_stored", result, steam_id);
}

// Callback indicating that a user's stats have been unloaded.
void SteamServer::stats_unloaded(GSStatsUnloaded_t *call_data) {
	uint64_t steam_id = call_data->m_steamIDUser.ConvertToUint64();
	emit_signal("stats_unloaded", steam_id);
}


///// HTTP

// Result when an HTTP request completes. If you're using GetHTTPStreamingResponseBodyData then you should be using the HTTPRequestHeadersReceived_t or HTTPRequestDataReceived_t.
void SteamServer::http_request_completed(HTTPRequestCompleted_t *call_data) {
	uint32 cookie_handle = call_data->m_hRequest;
	uint64_t context_value = call_data->m_ulContextValue;
	bool request_success = call_data->m_bRequestSuccessful;
	int status_code = call_data->m_eStatusCode;
	uint32 body_size = call_data->m_unBodySize;
	emit_signal("http_request_completed", cookie_handle, context_value, request_success, status_code, body_size);
}

// Triggered when a chunk of data is received from a streaming HTTP request.
void SteamServer::http_request_data_received(HTTPRequestDataReceived_t *call_data) {
	uint32 cookie_handle = call_data->m_hRequest;
	uint64_t context_value = call_data->m_ulContextValue;
	uint32 offset = call_data->m_cOffset;
	uint32 bytes_received = call_data->m_cBytesReceived;
	emit_signal("http_request_data_received", cookie_handle, context_value, offset, bytes_received);
}

// Triggered when HTTP headers are received from a streaming HTTP request.
void SteamServer::http_request_headers_received(HTTPRequestHeadersReceived_t *call_data) {
	uint32 cookie_handle = call_data->m_hRequest;
	uint64_t context_value = call_data->m_ulContextValue;
	emit_signal("http_request_headers_received", cookie_handle, context_value);
}


///// INVENTORY

// This callback is triggered whenever item definitions have been updated, which could be in response to LoadItemDefinitions or any time new item definitions are available (eg, from the dynamic addition of new item types while players are still in-game).
void SteamServer::inventory_definition_update(SteamInventoryDefinitionUpdate_t *call_data) {
	// Create the return array
	Array definitions;
	// Set the array size variable
	uint32 size = 0;
	// Get the item defition IDs
	if (SteamInventory()->GetItemDefinitionIDs(NULL, &size)) {
		SteamItemDef_t *id_array = new SteamItemDef_t[size];
		if (SteamInventory()->GetItemDefinitionIDs(id_array, &size)) {
			// Loop through the temporary array and populate the return array
			for (uint32 i = 0; i < size; i++) {
				definitions.append(id_array[i]);
			}
		}
		// Delete the temporary array
		delete[] id_array;
	}
	// Return the item array as a signal
	emit_signal("inventory_definition_update", definitions);
}

// Triggered when GetAllItems successfully returns a result which is newer / fresher than the last known result. (It will not trigger if the inventory hasn't changed, or if results from two overlapping calls are reversed in flight and the earlier result is already known to be stale/out-of-date.)
// The regular SteamInventoryResultReady_t callback will still be triggered immediately afterwards; this is an additional notification for your convenience.
void SteamServer::inventory_full_update(SteamInventoryFullUpdate_t *call_data) {
	// Set the handle
	inventory_handle = call_data->m_handle;
	// Send the handle back to the user
	emit_signal("inventory_full_update", call_data->m_handle);
}

// This is fired whenever an inventory result transitions from k_EResultPending to any other completed state, see GetResultStatus for the complete list of states. There will always be exactly one callback per handle.
void SteamServer::inventory_result_ready(SteamInventoryResultReady_t *call_data) {
	// Get the result
	int result = call_data->m_result;
	// Get the handle and pass it over
	inventory_handle = call_data->m_handle;
	emit_signal("inventory_result_ready", result, inventory_handle);
}


///// NETWORKING

// Called when packets can't get through to the specified user. All queued packets unsent at this point will be dropped, further attempts to send will retry making the connection (but will be dropped if we fail again).
void SteamServer::p2p_session_connect_fail(P2PSessionConnectFail_t *call_data) {
	uint64_t remote_steam_id = call_data->m_steamIDRemote.ConvertToUint64();
	uint8_t session_error = call_data->m_eP2PSessionError;
	emit_signal("p2p_session_connect_fail", remote_steam_id, session_error);
}

// A user wants to communicate with us over the P2P channel via the sendP2PPacket. In response, a call to acceptP2PSessionWithUser needs to be made, if you want to open the network channel with them.
void SteamServer::p2p_session_request(P2PSessionRequest_t *call_data) {
	uint64_t remote_steam_id = call_data->m_steamIDRemote.ConvertToUint64();
	emit_signal("p2p_session_request", remote_steam_id);
}


///// NETWORKING MESSAGES

// Posted when a remote host is sending us a message, and we do not already have a session with them.
void SteamServer::network_messages_session_request(SteamNetworkingMessagesSessionRequest_t *call_data) {
	emit_signal("network_messages_session_request", getSteamIDFromIdentity(call_data->m_identityRemote));
}

// Posted when we fail to establish a connection, or we detect that communications have been disrupted it an unusual way.
void SteamServer::network_messages_session_failed(SteamNetworkingMessagesSessionFailed_t *call_data) {
	SteamNetConnectionInfo_t info = call_data->m_info;
	int reason = info.m_eEndReason;
	uint64_t remote_steam_id = getSteamIDFromIdentity(info.m_identityRemote);
	int connection_state = (int)info.m_eState;
	String debug_message = (String)info.m_szEndDebug;
	emit_signal("network_messages_session_failed", reason, remote_steam_id, connection_state, debug_message);
}


///// NETWORKING SOCKETS

// A struct used to describe a "fake IP" we have been assigned to use as an identifier.
// This callback is posted when ISteamNetworkingSoockets::BeginAsyncRequestFakeIP completes.
void SteamServer::fake_ip_result(SteamNetworkingFakeIPResult_t *call_data) {
	int result = call_data->m_eResult;
	uint32 fake_ip = call_data->m_unIP;
	// Get the ports as an array
	Array port_list;
	uint16 *ports = call_data->m_unPorts;
	for (uint16 i = 0; i < sizeof(ports); i++) {
		port_list.append(ports[i]);
	}
	emit_signal("fake_ip_result", result, getSteamIDFromIdentity(call_data->m_identity), getStringFromIP(fake_ip), port_list);
}

// This callback is posted whenever the state of our readiness changes.
void SteamServer::network_authentication_status(SteamNetAuthenticationStatus_t *call_data) {
	int available = call_data->m_eAvail;
	// Non-localized English language status. For diagnostic / debugging purposes only.
	char debug_message[256 + 1]{};
	snprintf(debug_message, 256, "%s", call_data->m_debugMsg);
	// Send the data back via signal
	emit_signal("network_authentication_status", available, debug_message);
}

// This callback is posted whenever a connection is created, destroyed, or changes state. The m_info field will contain a complete description of the connection at the time the change occurred and the callback was posted. In particular, m_info.m_eState will have the new connection state.
void SteamServer::network_connection_status_changed(SteamNetConnectionStatusChangedCallback_t *call_data) {
	uint32_t connection_handle = call_data->m_hConn;
	SteamNetConnectionInfo_t connection_info = call_data->m_info;

	Dictionary connection;
	connection["identity"] = getSteamIDFromIdentity(connection_info.m_identityRemote);
	connection["user_data"] = (uint64_t)connection_info.m_nUserData;
	connection["listen_socket"] = connection_info.m_hListenSocket;
	connection["remote_address"] = getStringFromSteamIP(connection_info.m_addrRemote);
	connection["remote_pop"] = connection_info.m_idPOPRemote;
	connection["pop_relay"] = connection_info.m_idPOPRelay;
	connection["connection_state"] = connection_info.m_eState;
	connection["end_reason"] = connection_info.m_eEndReason;
	connection["end_debug"] = connection_info.m_szEndDebug;
	connection["debug_description"] = connection_info.m_szConnectionDescription;
	// Previous state (current state is in m_info.m_eState).
	int old_state = call_data->m_eOldState;
	emit_signal("network_connection_status_changed", connection_handle, connection, old_state);
}


///// NETWORKING UTILS

// A struct used to describe our readiness to use the relay network.
void SteamServer::relay_network_status(SteamRelayNetworkStatus_t *call_data) {
	int available = call_data->m_eAvail;
	int ping_measurement = call_data->m_bPingMeasurementInProgress;
	int available_config = call_data->m_eAvailNetworkConfig;
	int available_relay = call_data->m_eAvailAnyRelay;
	char debug_message[256 + 1]{};
	snprintf(debug_message, 256, "%s", call_data->m_debugMsg);
//	debug_message = call_data->m_debugMsg;
	emit_signal("relay_network_status", available, ping_measurement, available_config, available_relay, debug_message);
}

///// REMOTE STORAGE

// Purpose: one or more files for this app have changed locally after syncing to remote session changes.
// Note: only posted if this happens DURING the local app session.
void SteamServer::local_file_changed(RemoteStorageLocalFileChange_t *call_data) {
	emit_signal("local_file_changed");
}

///// UGC

// Called when a workshop item has been downloaded.
void SteamServer::item_downloaded(DownloadItemResult_t *call_data) {
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	AppId_t app_id = call_data->m_unAppID;
	emit_signal("item_downloaded", result, (uint64_t)file_id, (uint32_t)app_id);
}

// Called when a workshop item has been installed or updated.
void SteamServer::item_installed(ItemInstalled_t *call_data) {
	AppId_t app_id = call_data->m_unAppID;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	UGCHandle_t legacy_content = call_data->m_hLegacyContent;
	uint64_t manifest_id = call_data->m_unManifestID;
	emit_signal("item_installed", app_id, (uint64_t)file_id, (uint64_t)legacy_content, manifest_id);
}

// Purpose: signal that the list of subscribed items changed.
void SteamServer::user_subscribed_items_list_changed(UserSubscribedItemsListChanged_t *call_data) {
	uint32 app_id = call_data->m_nAppID;
	emit_signal("user_subscribed_items_list_changed", app_id);
}


///// SIGNALS / CALL RESULTS

///// GAME SERVER

// Result when getting the latests stats and achievements for a user from the server.
void SteamServer::stats_received(GSStatsReceived_t *callData, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] stats_received signal failed internally");
	EResult result = callData->m_eResult;
	uint64_t steam_id = callData->m_steamIDUser.ConvertToUint64();
	emit_signal("stats_received", result, steam_id);
}


///// INVENTORY

// Returned when you have requested the list of "eligible" promo items that can be manually granted to the given user. These are promo items of type "manual" that won't be granted automatically.
void SteamServer::inventory_eligible_promo_item(SteamInventoryEligiblePromoItemDefIDs_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] inventory_eligible_promo_item signal failed internally");
	CSteamID steam_id = call_data->m_steamID;
	int result = call_data->m_result;
	int eligible = call_data->m_numEligiblePromoItemDefs;
	bool cached = call_data->m_bCachedData;
	Array definitions;
	SteamItemDef_t *id_array = new SteamItemDef_t[eligible];
	uint32 array_size = (int)eligible;
	
	if (SteamInventory()->GetEligiblePromoItemDefinitionIDs(steam_id, id_array, &array_size)) {
		for (int i = 0; i < eligible; i++) {
			definitions.append(id_array[i]);
		}
	}
	delete[] id_array;
	emit_signal("inventory_eligible_promo_Item", result, cached, definitions);
}

// Returned after StartPurchase is called.
void SteamServer::inventory_start_purchase_result(SteamInventoryStartPurchaseResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] inventory_start_purchase_result signal failed internally");
	if (call_data->m_result == k_EResultOK) {
		uint64_t order_id = call_data->m_ulOrderID;
		uint64_t transaction_id = call_data->m_ulTransID;
		emit_signal("inventory_start_purchase_result", "success", order_id, transaction_id);
	}
	else {
		emit_signal("inventory_start_purchase_result", "failure", 0, 0);
	}
}

// Returned after RequestPrices is called.
void SteamServer::inventory_request_prices_result(SteamInventoryRequestPricesResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] inventory_request_prices_result signal failed internally");
	int result = call_data->m_result;
	String currency = call_data->m_rgchCurrency;
	emit_signal("inventory_request_prices_result", result, currency);
}


///// REMOTE STORAGE

// Response when reading a file asyncrounously with FileReadAsync.
void SteamServer::file_read_async_complete(RemoteStorageFileReadAsyncComplete_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] file_read_async_complete signal failed internally");
	uint64_t handle = call_data->m_hFileReadAsync;
	int result = call_data->m_eResult;
	uint32 offset = call_data->m_nOffset;
	uint32 read = call_data->m_cubRead;
	// Was read complete?
	PoolByteArray buffer;
	buffer.resize(read);
	bool complete = SteamRemoteStorage()->FileReadAsyncComplete(handle, buffer.write().ptr(), read);
	// Create a dictionary and populate it with the results
	Dictionary file_read;
	file_read["result"] = result;
	file_read["handle"] = handle;
	file_read["buffer"] = buffer;
	file_read["offset"] = offset;
	file_read["read"] = read;
	file_read["complete"] = complete;
	emit_signal("file_read_async_complete", file_read);
}

// Response to a file being shared.
void SteamServer::file_share_result(RemoteStorageFileShareResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] file_share_result signal failed internally");
	int result = call_data->m_eResult;
	uint64_t handle = call_data->m_hFile;
	const char *name = call_data->m_rgchFilename;
	emit_signal("file_share_result", result, handle, name);
}

// Response when writing a file asyncrounously with FileWriteAsync.
void SteamServer::file_write_async_complete(RemoteStorageFileWriteAsyncComplete_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] file_write_async_complete signal failed internally");
	int result = call_data->m_eResult;
	emit_signal("file_write_async_complete", result);
}

// Response when downloading UGC
void SteamServer::download_ugc_result(RemoteStorageDownloadUGCResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] download_ugc_result signal failed internally");
	int result = call_data->m_eResult;
	uint64_t handle = call_data->m_hFile;
	uint32_t app_id = call_data->m_nAppID;
	int32 size = call_data->m_nSizeInBytes;
	const char *filename = call_data->m_pchFileName;
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

// Called when the user has unsubscribed from a piece of UGC. Result from ISteamUGC::UnsubscribeItem.
void SteamServer::unsubscribe_item(RemoteStorageUnsubscribePublishedFileResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] unsubscribe_item signal failed internally");
	int result = call_data->m_eResult;
	int file_id = call_data->m_nPublishedFileId;
	emit_signal("unsubscribe_item", result, file_id);
}

// Called when the user has subscribed to a piece of UGC. Result from ISteamUGC::SubscribeItem.
void SteamServer::subscribe_item(RemoteStorageSubscribePublishedFileResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] subscribe_item signal failed internally");
	int result = call_data->m_eResult;
	int file_id = call_data->m_nPublishedFileId;
	emit_signal("subscribe_item", result, file_id);
}


///// UGC

// The result of a call to AddAppDependency.
void SteamServer::add_app_dependency_result(AddAppDependencyResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] add_app_dependency_result signal failed internally");
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	AppId_t app_id = call_data->m_nAppID;
	emit_signal("add_app_dependency_result", result, (uint64_t)file_id, (uint32_t)app_id);
}

// The result of a call to AddDependency.
void SteamServer::add_ugc_dependency_result(AddUGCDependencyResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] add_ugc_dependency_result signal failed internally");
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	PublishedFileId_t child_id = call_data->m_nChildPublishedFileId;
	emit_signal("add_ugc_dependency_result", result, (uint64_t)file_id, (uint64_t)child_id);
}

// Called when getting the app dependencies for an item.
void SteamServer::get_app_dependencies_result(GetAppDependenciesResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] get_app_dependencies_result signal failed internally");
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	uint32 app_dependencies = call_data->m_nNumAppDependencies;
	uint32 total_app_dependencies = call_data->m_nTotalNumAppDependencies;
	PoolIntArray app_ids;
	for (uint32 i = 0; i < app_dependencies; i++) {
		app_ids.append(call_data->m_rgAppIDs[i]);
	}
	emit_signal("get_app_dependencies_result", result, (uint64_t)file_id, app_ids, app_dependencies, total_app_dependencies);
}

// Called when getting the users vote status on an item.
void SteamServer::get_item_vote_result(GetUserItemVoteResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] get_item_vote_result signal failed internally");
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	bool vote_up = call_data->m_bVotedUp;
	bool vote_down = call_data->m_bVotedDown;
	bool vote_skipped = call_data->m_bVoteSkipped;
	emit_signal("get_item_vote_result", result, (uint64_t)file_id, vote_up, vote_down, vote_skipped);
}
// Result of a workshop item being created.
void SteamServer::item_created(CreateItemResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] item_created signal failed internally");
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	bool accept_tos = call_data->m_bUserNeedsToAcceptWorkshopLegalAgreement;
	emit_signal("item_created", result, (uint64_t)file_id, accept_tos);
}

// Called when an attempt at deleting an item completes.
void SteamServer::item_deleted(DeleteItemResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] add_ugc_dependency_result signal failed internally");
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	emit_signal("item_deleted", result, (uint64_t)file_id);
}

// Result of a workshop item being updated.
void SteamServer::item_updated(SubmitItemUpdateResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] get_item_vote_result signal failed internally");
	EResult result = call_data->m_eResult;
	bool need_to_accept_tos = call_data->m_bUserNeedsToAcceptWorkshopLegalAgreement;
	emit_signal("item_updated", result, need_to_accept_tos);
}

// Purpose: The result of a call to RemoveAppDependency.
void SteamServer::remove_app_dependency_result(RemoveAppDependencyResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] remove_app_dependency_result signal failed internally");
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	AppId_t app_id = call_data->m_nAppID;
	emit_signal("remove_app_dependency_result", result, (uint64_t)file_id, (uint32_t)app_id);
}

// Purpose: The result of a call to RemoveDependency.
void SteamServer::remove_ugc_dependency_result(RemoveUGCDependencyResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] remove_ugc_dependency_result signal failed internally");
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	PublishedFileId_t child_id = call_data->m_nChildPublishedFileId;
	emit_signal("remove_ugc_dependency_result", result, (uint64_t)file_id, (uint64_t)child_id);
}

// Called when the user has voted on an item.
void SteamServer::set_user_item_vote(SetUserItemVoteResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] set_user_item_vote signal failed internally");
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	bool vote_up = call_data->m_bVoteUp;
	emit_signal("set_user_item_vote", result, (uint64_t)file_id, vote_up);
}

// Called when workshop item playtime tracking has started.
void SteamServer::start_playtime_tracking(StartPlaytimeTrackingResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] start_playtime_tracking signal failed internally");
	EResult result = call_data->m_eResult;
	emit_signal("start_playtime_tracking", result);
}

// Called when workshop item playtime tracking has stopped.
void SteamServer::stop_playtime_tracking(StopPlaytimeTrackingResult_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] get_item_vote_result signal failed internally");
	EResult result = call_data->m_eResult;
	emit_signal("stop_playtime_tracking", result);
}

// Called when a UGC query request completes.
void SteamServer::ugc_query_completed(SteamUGCQueryCompleted_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] ugc_query_completed signal failed internally");
	UGCQueryHandle_t handle = call_data->m_handle;
	EResult result = call_data->m_eResult;
	uint32 results_returned = call_data->m_unNumResultsReturned;
	uint32 total_matching = call_data->m_unTotalMatchingResults;
	bool cached = call_data->m_bCachedData;
	emit_signal("ugc_query_completed", (uint64_t)handle, result, results_returned, total_matching, cached);
}

// Called when the user has added or removed an item to/from their favorites.
void SteamServer::user_favorite_items_list_changed(UserFavoriteItemsListChanged_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] get_item_vote_result signal failed internally");
	EResult result = call_data->m_eResult;
	PublishedFileId_t file_id = call_data->m_nPublishedFileId;
	bool was_add_request = call_data->m_bWasAddRequest;
	emit_signal("user_favorite_items_list_changed", result, (uint64_t)file_id, was_add_request);
}

// Purpose: Status of the user's acceptable/rejection of the app's specific Workshop EULA.
void SteamServer::workshop_eula_status(WorkshopEULAStatus_t *call_data, bool io_failure) {
	ERR_FAIL_COND_MSG(io_failure, "[STEAM SERVER] get_item_vote_result signal failed internally");
	int result = call_data->m_eResult;
	uint32 app_id = call_data->m_nAppID;
	
	Dictionary eula_data;
	eula_data["version"] = call_data->m_unVersion;	// int
	eula_data["action"] = call_data->m_rtAction;	// int
	eula_data["accepted"] = call_data->m_bAccepted;	// bool
	eula_data["needs_action"] = call_data->m_bNeedsAction;	// bool
	emit_signal("workshop_eula_status", result, app_id, eula_data);
}


///// BIND METHODS

void SteamServer::_bind_methods() {

	// STEAM MAIN
	ClassDB::bind_method("getServerSteamID", &SteamServer::getServerSteamID);
	ClassDB::bind_method(D_METHOD("getSteamID32", "steam_id"), &SteamServer::getSteamID32);
	ClassDB::bind_method(D_METHOD("isAnonAccount", "steam_id"), &SteamServer::isAnonAccount);
	ClassDB::bind_method(D_METHOD("isAnonUserAccount", "steam_id"), &SteamServer::isAnonUserAccount);
	ClassDB::bind_method(D_METHOD("isChatAccount", "steam_id"), &SteamServer::isChatAccount);
	ClassDB::bind_method(D_METHOD("isClanAccount", "steam_id"), &SteamServer::isClanAccount);
	ClassDB::bind_method(D_METHOD("isConsoleUserAccount", "steam_id"), &SteamServer::isConsoleUserAccount);
	ClassDB::bind_method(D_METHOD("isIndividualAccount", "steam_id"), &SteamServer::isIndividualAccount);
	ClassDB::bind_method(D_METHOD("isLobby", "steam_id"), &SteamServer::isLobby);
	ClassDB::bind_method("isServerSecure", &SteamServer::isServerSecure);
	ClassDB::bind_method("run_callbacks", &SteamServer::run_callbacks);
	ClassDB::bind_method(D_METHOD("serverInit", "ip", "game_port", "query_port", "server_mode", "version_number"), &SteamServer::serverInit);
	ClassDB::bind_method(D_METHOD("serverInitEx", "ip", "game_port", "query_port", "server_mode", "version_number"), &SteamServer::serverInitEx);
	ClassDB::bind_method("serverReleaseCurrentThreadMemory", &SteamServer::serverReleaseCurrentThreadMemory);
	ClassDB::bind_method("serverShutdown", &SteamServer::serverShutdown);

	ClassDB::bind_method("get_godotsteam_version", &SteamServer::get_godotsteam_version);
	ClassDB::bind_method("get_inventory_handle", &SteamServer::get_inventory_handle);
	ClassDB::bind_method("get_inventory_update_handle", &SteamServer::get_inventory_update_handle);
	ClassDB::bind_method(D_METHOD("set_inventory_handle", "new_inventory_handle"), &SteamServer::set_inventory_handle);
	ClassDB::bind_method(D_METHOD("set_inventory_update_handle", "new_inventory_update_handle"), &SteamServer::set_inventory_update_handle);

	// GAME SERVER
	ClassDB::bind_method(D_METHOD("associateWithClan", "clan_id"), &SteamServer::associateWithClan);
	ClassDB::bind_method(D_METHOD("beginAuthSession", "ticket", "ticket_size", "steam_id"), &SteamServer::beginAuthSession);
	ClassDB::bind_method(D_METHOD("cancelAuthTicket", "auth_ticket"), &SteamServer::cancelAuthTicket);
	ClassDB::bind_method("clearAllKeyValues", &SteamServer::clearAllKeyValues);
	ClassDB::bind_method(D_METHOD("computeNewPlayerCompatibility", "steam_id"), &SteamServer::computeNewPlayerCompatibility);
	ClassDB::bind_method(D_METHOD("endAuthSession", "steam_id"), &SteamServer::endAuthSession);
	ClassDB::bind_method(D_METHOD("getAuthSessionTicket", "remote_steam_id"), &SteamServer::getAuthSessionTicket, DEFVAL(0));
	ClassDB::bind_method("getNextOutgoingPacket", &SteamServer::getNextOutgoingPacket);
	ClassDB::bind_method("getPublicIP", &SteamServer::getPublicIP);
	ClassDB::bind_method("getSteamID", &SteamServer::getSteamID);
	ClassDB::bind_method(D_METHOD("handleIncomingPacket", "packet", "ip", "port"), &SteamServer::handleIncomingPacket);
	ClassDB::bind_method("loggedOn", &SteamServer::loggedOn);
	ClassDB::bind_method("logOff", &SteamServer::logOff);
	ClassDB::bind_method(D_METHOD("logOn", "token"), &SteamServer::logOn);
	ClassDB::bind_method("logOnAnonymous", &SteamServer::logOnAnonymous);
	ClassDB::bind_method(D_METHOD("requestUserGroupStatus", "steam_id", "group_id"), &SteamServer::requestUserGroupStatus);
	ClassDB::bind_method("secure", &SteamServer::secure);
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
	ClassDB::bind_method("wasRestartRequested", &SteamServer::wasRestartRequested);	
	
	// GAME SERVER STATS
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

	// HTTP
	ClassDB::bind_method(D_METHOD("createCookieContainer", "allow_response_to_modify"), &SteamServer::createCookieContainer);
	ClassDB::bind_method(D_METHOD("createHTTPRequest", "request_method", "absolute_url"), &SteamServer::createHTTPRequest);
	ClassDB::bind_method(D_METHOD("deferHTTPRequest", "request_handle"), &SteamServer::deferHTTPRequest);
	ClassDB::bind_method(D_METHOD("getHTTPDownloadProgressPct", "request_handle"), &SteamServer::getHTTPDownloadProgressPct);
	ClassDB::bind_method(D_METHOD("getHTTPRequestWasTimedOut", "request_handle"), &SteamServer::getHTTPRequestWasTimedOut);
	ClassDB::bind_method(D_METHOD("getHTTPResponseBodyData", "request_handle", "buffer_size"), &SteamServer::getHTTPResponseBodyData);
	ClassDB::bind_method(D_METHOD("getHTTPResponseBodySize", "request_handle"), &SteamServer::getHTTPResponseBodySize);
	ClassDB::bind_method(D_METHOD("getHTTPResponseHeaderSize", "request_handle", "header_name"), &SteamServer::getHTTPResponseHeaderSize);
	ClassDB::bind_method(D_METHOD("getHTTPResponseHeaderValue", "request_handle", "header_name", "buffer_size"), &SteamServer::getHTTPResponseHeaderValue);
//	ClassDB::bind_method(D_METHOD("getHTTPStreamingResponseBodyData", "request_handle", "offset", "buffer_size"), &SteamServer::getHTTPStreamingResponseBodyData);
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
	ClassDB::bind_method(D_METHOD("setHTTPRequestRawPostBody", "request_handle", "content_type", "body"), &SteamServer::setHTTPRequestRawPostBody);
	ClassDB::bind_method(D_METHOD("setHTTPRequestRequiresVerifiedCertificate", "request_handle", "require_verified_certificate"), &SteamServer::setHTTPRequestRequiresVerifiedCertificate);
	ClassDB::bind_method(D_METHOD("setHTTPRequestUserAgentInfo", "request_handle", "user_agent_info"), &SteamServer::setHTTPRequestUserAgentInfo);

	// INVENTORY
	ClassDB::bind_method(D_METHOD("addPromoItem", "item"), &SteamServer::addPromoItem);
	ClassDB::bind_method(D_METHOD("addPromoItems", "items"), &SteamServer::addPromoItems);
	ClassDB::bind_method(D_METHOD("checkResultSteamID", "steam_id_expected", "this_inventory_handle"), &SteamServer::checkResultSteamID, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("consumeItem", "item_consume", "quantity"), &SteamServer::consumeItem);
	ClassDB::bind_method(D_METHOD("deserializeResult", "buffer"), &SteamServer::deserializeResult);
	ClassDB::bind_method(D_METHOD("destroyResult", "this_inventory_handle"), &SteamServer::destroyResult, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("exchangeItems", "output_items", "output_quantity", "input_items", "input_quantity"), &SteamServer::exchangeItems);
	ClassDB::bind_method(D_METHOD("generateItems", "items", "quantity"), &SteamServer::generateItems);
	ClassDB::bind_method("getAllItems", &SteamServer::getAllItems);
	ClassDB::bind_method(D_METHOD("getItemDefinitionProperty", "definition", "name"), &SteamServer::getItemDefinitionProperty);
	ClassDB::bind_method(D_METHOD("getItemsByID", "id_array"), &SteamServer::getItemsByID);
	ClassDB::bind_method(D_METHOD("getItemPrice", "definition"), &SteamServer::getItemPrice);
	ClassDB::bind_method(D_METHOD("getItemsWithPrices"), &SteamServer::getItemsWithPrices);
	ClassDB::bind_method(D_METHOD("getResultItemProperty", "index", "name", "this_inventory_handle"), &SteamServer::getResultItemProperty, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("getResultItems", "this_inventory_handle"), &SteamServer::getResultItems, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("getResultStatus", "this_inventory_handle"), &SteamServer::getResultStatus, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("getResultTimestamp", "this_inventory_handle"), &SteamServer::getResultTimestamp, DEFVAL(0));
	ClassDB::bind_method("grantPromoItems", &SteamServer::grantPromoItems);
	ClassDB::bind_method("loadItemDefinitions", &SteamServer::loadItemDefinitions);
	ClassDB::bind_method(D_METHOD("requestEligiblePromoItemDefinitionsIDs", "steam_id"), &SteamServer::requestEligiblePromoItemDefinitionsIDs);
	ClassDB::bind_method("requestPrices", &SteamServer::requestPrices);
	ClassDB::bind_method(D_METHOD("serializeResult", "this_inventory_handle"), &SteamServer::serializeResult, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("startPurchase", "items", "quantity"), &SteamServer::startPurchase);
	ClassDB::bind_method(D_METHOD("transferItemQuantity", "item_id", "quantity", "item_destination", "split"), &SteamServer::transferItemQuantity);
	ClassDB::bind_method(D_METHOD("triggerItemDrop", "definition"), &SteamServer::triggerItemDrop);
	ClassDB::bind_method("startUpdateProperties", &SteamServer::startUpdateProperties);
	ClassDB::bind_method(D_METHOD("submitUpdateProperties", "this_inventory_update_handle"), &SteamServer::submitUpdateProperties, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("removeProperty", "item_id", "name", "this_inventory_update_handle"), &SteamServer::removeProperty, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("setPropertyString", "item_id", "name", "value", "this_inventory_update_handle"), &SteamServer::setPropertyString, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("setPropertyBool", "item_id", "name", "value", "this_inventory_update_handle"), &SteamServer::setPropertyBool, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("setPropertyInt", "item_id", "name", "value", "this_inventory_update_handle"), &SteamServer::setPropertyInt, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("setPropertyFloat", "item_id", "name", "value", "this_inventory_update_handle"), &SteamServer::setPropertyFloat, DEFVAL(0));

	// NETWORKING
	ClassDB::bind_method(D_METHOD("acceptP2PSessionWithUser", "remote_steam_id"), &SteamServer::acceptP2PSessionWithUser);
	ClassDB::bind_method(D_METHOD("allowP2PPacketRelay", "allow"), &SteamServer::allowP2PPacketRelay);
	ClassDB::bind_method(D_METHOD("closeP2PChannelWithUser", "remote_steam_id", "channel"), &SteamServer::closeP2PChannelWithUser);
	ClassDB::bind_method(D_METHOD("closeP2PSessionWithUser", "remote_steam_id"), &SteamServer::closeP2PSessionWithUser);
	ClassDB::bind_method(D_METHOD("getP2PSessionState", "remote_steam_id"), &SteamServer::getP2PSessionState);
	ClassDB::bind_method(D_METHOD("getAvailableP2PPacketSize", "channel"), &SteamServer::getAvailableP2PPacketSize, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("readP2PPacket", "packet", "channel"), &SteamServer::readP2PPacket, DEFVAL(0));
	ClassDB::bind_method(D_METHOD("sendP2PPacket", "remote_steam_id", "data", "send_type", "channel"), &SteamServer::sendP2PPacket, DEFVAL(0));

	// NETWORKING MESSAGES
	ClassDB::bind_method(D_METHOD("acceptSessionWithUser", "remote_steam_id"), &SteamServer::acceptSessionWithUser);
	ClassDB::bind_method(D_METHOD("closeChannelWithUser", "remote_steam_id", "channel"), &SteamServer::closeChannelWithUser);
	ClassDB::bind_method(D_METHOD("closeSessionWithUser", "remote_steam_id"), &SteamServer::closeSessionWithUser);
	ClassDB::bind_method(D_METHOD("getSessionConnectionInfo", "remote_steam_id", "get_connection", "get_status"), &SteamServer::getSessionConnectionInfo);
	ClassDB::bind_method(D_METHOD("receiveMessagesOnChannel", "channel", "max_messages"), &SteamServer::receiveMessagesOnChannel);
	ClassDB::bind_method(D_METHOD("sendMessageToUser", "remote_steam_id", "data", "flags", "channel"), &SteamServer::sendMessageToUser);

	// NETWORKING SOCKETS
	ClassDB::bind_method(D_METHOD("acceptConnection", "connection_handle"), &SteamServer::acceptConnection);
	ClassDB::bind_method(D_METHOD("beginAsyncRequestFakeIP", "num_ports"), &SteamServer::beginAsyncRequestFakeIP);
	ClassDB::bind_method(D_METHOD("closeConnection", "peer", "reason", "debug_message", "linger"), &SteamServer::closeConnection);
	ClassDB::bind_method(D_METHOD("closeListenSocket", "socket"), &SteamServer::closeListenSocket);
	ClassDB::bind_method(D_METHOD("configureConnectionLanes", "connection", "lanes", "priorities", "weights"), &SteamServer::configureConnectionLanes);
	ClassDB::bind_method(D_METHOD("connectP2P", "remote_steam_id", "virtual_port", "options"), &SteamServer::connectP2P);
	ClassDB::bind_method(D_METHOD("connectByIPAddress", "ip_address_with_port", "options"), &SteamServer::connectByIPAddress);
	ClassDB::bind_method(D_METHOD("connectToHostedDedicatedServer", "remote_steam_id", "virtual_port", "options"), &SteamServer::connectToHostedDedicatedServer);
	ClassDB::bind_method(D_METHOD("createFakeUDPPort", "fake_server_port"), &SteamServer::createFakeUDPPort);
	ClassDB::bind_method(D_METHOD("createHostedDedicatedServerListenSocket", "virtual_port", "options"), &SteamServer::createHostedDedicatedServerListenSocket);
	ClassDB::bind_method(D_METHOD("createListenSocketIP", "ip_reference", "options"), &SteamServer::createListenSocketIP);
	ClassDB::bind_method(D_METHOD("createListenSocketP2P", "virtual_port", "options"), &SteamServer::createListenSocketP2P);
	ClassDB::bind_method(D_METHOD("createListenSocketP2PFakeIP", "fake_port", "options"), &SteamServer::createListenSocketP2PFakeIP);
	ClassDB::bind_method("createPollGroup", &SteamServer::createPollGroup);
	ClassDB::bind_method(D_METHOD("createSocketPair", "loopback", "remote_steam_id1", "remote_steam_id2"), &SteamServer::createSocketPair);
	ClassDB::bind_method(D_METHOD("destroyPollGroup", "poll_group"), &SteamServer::destroyPollGroup);
//	ClassDB::bind_method(D_METHOD("findRelayAuthTicketForServer", "port"), &SteamServer::findRelayAuthTicketForServer);	<------ Uses datagram relay structs which were removed from base SDK
	ClassDB::bind_method(D_METHOD("flushMessagesOnConnection", "connection_handle"), &SteamServer::flushMessagesOnConnection);
	ClassDB::bind_method("getAuthenticationStatus", &SteamServer::getAuthenticationStatus);
	ClassDB::bind_method("getCertificateRequest", &SteamServer::getCertificateRequest);
	ClassDB::bind_method(D_METHOD("getConnectionInfo", "connection_handle"), &SteamServer::getConnectionInfo);
	ClassDB::bind_method(D_METHOD("getConnectionName", "peer"), &SteamServer::getConnectionName);
	ClassDB::bind_method(D_METHOD("getConnectionRealTimeStatus", "connection_handle", "lanes", "get_status"), &SteamServer::getConnectionRealTimeStatus, DEFVAL(true));
	ClassDB::bind_method(D_METHOD("getConnectionUserData", "peer"), &SteamServer::getConnectionUserData);
	ClassDB::bind_method(D_METHOD("getDetailedConnectionStatus", "connection_handle"), &SteamServer::getDetailedConnectionStatus);
	ClassDB::bind_method(D_METHOD("getFakeIP", "first_port"), &SteamServer::getFakeIP, DEFVAL(0));
//	ClassDB::bind_method(D_METHOD("getGameCoordinatorServerLogin", "app_data"), &SteamServer::getGameCoordinatorServerLogin);	<------ Uses datagram relay structs which were removed from base SDK
//	ClassDB::bind_method("getHostedDedicatedServerAddress", &SteamServer::getHostedDedicatedServerAddress);	<------ Uses datagram relay structs which were removed from base SDK
	ClassDB::bind_method("getHostedDedicatedServerPOPId", &SteamServer::getHostedDedicatedServerPOPId);
	ClassDB::bind_method("getHostedDedicatedServerPort", &SteamServer::getHostedDedicatedServerPort);
	ClassDB::bind_method(D_METHOD("getListenSocketAddress", "socket", "with_port"), &SteamServer::getListenSocketAddress, DEFVAL(true));
	ClassDB::bind_method(D_METHOD("getRemoteFakeIPForConnection", "connection"), &SteamServer::getRemoteFakeIPForConnection);
	ClassDB::bind_method("initAuthentication", &SteamServer::initAuthentication);
	ClassDB::bind_method(D_METHOD("receiveMessagesOnConnection", "connection", "max_messages"), &SteamServer::receiveMessagesOnConnection);
	ClassDB::bind_method(D_METHOD("receiveMessagesOnPollGroup", "poll_group", "max_messages"), &SteamServer::receiveMessagesOnPollGroup);
//	ClassDB::bind_method("receivedRelayAuthTicket", &SteamServer::receivedRelayAuthTicket);	<------ Uses datagram relay structs which were removed from base SDK
	ClassDB::bind_method(D_METHOD("resetIdentity", "remote_steam_id"), &SteamServer::resetIdentity);
	ClassDB::bind_method("runNetworkingCallbacks", &SteamServer::runNetworkingCallbacks);
//	ClassDB::bind_method(D_METHOD("sendMessages", "data", "connection_handle", "flags"), &Steam::sendMessages);		<------ Currently does not compile on Windows but does on Linux
	ClassDB::bind_method(D_METHOD("sendMessageToConnection", "connection_handle", "data", "flags"), &SteamServer::sendMessageToConnection);
	ClassDB::bind_method(D_METHOD("setCertificate", "certificate"), &SteamServer::setCertificate);
	ClassDB::bind_method(D_METHOD("setConnectionPollGroup", "connection_handle", "poll_group"), &SteamServer::setConnectionPollGroup);
	ClassDB::bind_method(D_METHOD("setConnectionName", "peer", "name"), &SteamServer::setConnectionName);

	// NETWORKING UTILS
	ClassDB::bind_method(D_METHOD("checkPingDataUpToDate", "max_age_in_seconds"), &SteamServer::checkPingDataUpToDate);
	ClassDB::bind_method(D_METHOD("convertPingLocationToString", "location"), &SteamServer::convertPingLocationToString);
	ClassDB::bind_method(D_METHOD("estimatePingTimeBetweenTwoLocations", "location1", "location2"), &SteamServer::estimatePingTimeBetweenTwoLocations);
	ClassDB::bind_method(D_METHOD("estimatePingTimeFromLocalHost", "location"), &SteamServer::estimatePingTimeFromLocalHost);
	ClassDB::bind_method(D_METHOD("getConfigValue", "config_value", "scope_type", "connection_handle"), &SteamServer::getConfigValue);
	ClassDB::bind_method(D_METHOD("getConfigValueInfo", "config_value"), &SteamServer::getConfigValueInfo);
	ClassDB::bind_method(D_METHOD("getDirectPingToPOP", "pop_id"), &SteamServer::getDirectPingToPOP);
	ClassDB::bind_method("getLocalPingLocation", &SteamServer::getLocalPingLocation);
	ClassDB::bind_method("getLocalTimestamp", &SteamServer::getLocalTimestamp);
	ClassDB::bind_method(D_METHOD("getPingToDataCenter", "pop_id"), &SteamServer::getPingToDataCenter);
	ClassDB::bind_method("getPOPCount", &SteamServer::getPOPCount);
	ClassDB::bind_method("getPOPList", &SteamServer::getPOPList);
	ClassDB::bind_method("getRelayNetworkStatus", &SteamServer::getRelayNetworkStatus);
	ClassDB::bind_method("initRelayNetworkAccess", &SteamServer::initRelayNetworkAccess);
	ClassDB::bind_method(D_METHOD("parsePingLocationString", "string"), &SteamServer::parsePingLocationString);
	ClassDB::bind_method(D_METHOD("setConnectionConfigValueFloat", "connection", "config", "value"), &SteamServer::setConnectionConfigValueFloat);
	ClassDB::bind_method(D_METHOD("setConnectionConfigValueInt32", "connection", "config", "value"), &SteamServer::setConnectionConfigValueInt32);
	ClassDB::bind_method(D_METHOD("setConnectionConfigValueString", "connection", "config", "value"), &SteamServer::setConnectionConfigValueString);
//	ClassDB::bind_method(D_METHOD("setConfigValue", "setting", "scope_type", "connection_handle", "data_type", "value"), &SteamServer::setConfigValue);
	ClassDB::bind_method(D_METHOD("setGlobalConfigValueFloat", "config", "value"), &SteamServer::setGlobalConfigValueFloat);
	ClassDB::bind_method(D_METHOD("setGlobalConfigValueInt32", "config", "value"), &SteamServer::setGlobalConfigValueInt32);
	ClassDB::bind_method(D_METHOD("setGlobalConfigValueString", "config", "value"), &SteamServer::setGlobalConfigValueString);

	// UGC
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
	ClassDB::bind_method(D_METHOD("initWorkshopForGameServer", "workshop_depot_id", "folder"), &SteamServer::initWorkshopForGameServer);
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
	ClassDB::bind_method("getNumSubscribedItems", &SteamServer::getNumSubscribedItems);
	ClassDB::bind_method(D_METHOD("getNumSupportedGameVersions", "query_handle", "index"), &SteamServer::getNumSupportedGameVersions);
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
	ClassDB::bind_method("getSubscribedItems", &SteamServer::getSubscribedItems);
	ClassDB::bind_method(D_METHOD("getSupportedGameVersionData", "query_handle", "index", "version_index"), &SteamServer::getSupportedGameVersionData);
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
	ClassDB::bind_method(D_METHOD("setAdminQuery", "update_handle", "admin_query"), &SteamServer::setAdminQuery);
	ClassDB::bind_method(D_METHOD("setAllowCachedResponse", "update_handle", "max_age_seconds"), &SteamServer::setAllowCachedResponse);
	ClassDB::bind_method(D_METHOD("setCloudFileNameFilter", "update_handle", "match_cloud_filename"), &SteamServer::setCloudFileNameFilter);
	ClassDB::bind_method(D_METHOD("setItemContent", "update_handle", "content_folder"), &SteamServer::setItemContent);
	ClassDB::bind_method(D_METHOD("setItemDescription", "update_handle", "description"), &SteamServer::setItemDescription);
	ClassDB::bind_method(D_METHOD("setItemMetadata", "update_handle", "ugc_metadata"), &SteamServer::setItemMetadata);
	ClassDB::bind_method(D_METHOD("setItemPreview", "update_handle", "preview_file"), &SteamServer::setItemPreview);
	ClassDB::bind_method(D_METHOD("setItemTags", "update_handle", "tag_array", "allow_admin_tags"), &SteamServer::setItemTags, DEFVAL(false));
	ClassDB::bind_method(D_METHOD("setItemTitle", "update_handle", "title"), &SteamServer::setItemTitle);
	ClassDB::bind_method(D_METHOD("setItemUpdateLanguage", "update_handle", "language"), &SteamServer::setItemUpdateLanguage);
	ClassDB::bind_method(D_METHOD("setItemVisibility", "update_handle", "visibility"), &SteamServer::setItemVisibility);
	ClassDB::bind_method(D_METHOD("setLanguage", "query_handle", "language"), &SteamServer::setLanguage);
	ClassDB::bind_method(D_METHOD("setMatchAnyTag", "query_handle", "match_any_tag"), &SteamServer::setMatchAnyTag);
	ClassDB::bind_method(D_METHOD("setRankedByTrendDays", "query_handle", "days"), &SteamServer::setRankedByTrendDays);
	ClassDB::bind_method(D_METHOD("setRequiredGameVersions", "query_handle", "game_branch_min", "game_branch_max"), &SteamServer::setRequiredGameVersions);
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
	ClassDB::bind_method("stopPlaytimeTrackingForAllItems", &SteamServer::stopPlaytimeTrackingForAllItems);
	ClassDB::bind_method(D_METHOD("getAppDependencies", "published_file_id"), &SteamServer::getAppDependencies);
	ClassDB::bind_method(D_METHOD("submitItemUpdate", "update_handle", "change_note"), &SteamServer::submitItemUpdate);
	ClassDB::bind_method(D_METHOD("subscribeItem", "published_file_id"), &SteamServer::subscribeItem);
	ClassDB::bind_method(D_METHOD("suspendDownloads", "suspend"), &SteamServer::suspendDownloads);
	ClassDB::bind_method(D_METHOD("unsubscribeItem", "published_file_id"), &SteamServer::unsubscribeItem);
	ClassDB::bind_method(D_METHOD("updateItemPreviewFile", "update_handle", "index", "preview_file"), &SteamServer::updateItemPreviewFile);
	ClassDB::bind_method(D_METHOD("updateItemPreviewVideo", "update_handle", "index", "video_id"), &SteamServer::updateItemPreviewVideo);
	ClassDB::bind_method("showWorkshopEULA", &SteamServer::showWorkshopEULA);
	ClassDB::bind_method("getWorkshopEULAStatus", &SteamServer::getWorkshopEULAStatus);
	ClassDB::bind_method(D_METHOD("setTimeCreatedDateRange", "update_handle", "start", "end"), &SteamServer::setTimeCreatedDateRange);
	ClassDB::bind_method(D_METHOD("setTimeUpdatedDateRange", "update_handle", "start", "end"), &SteamServer::setTimeUpdatedDateRange);


	///// SIGNALS / CALLBACKS

	// GAME SERVER
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
	
	// GAME SERVER STATS
	ADD_SIGNAL(MethodInfo("stats_received", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "steam_id")));
	ADD_SIGNAL(MethodInfo("stats_stored", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "steam_id")));
	ADD_SIGNAL(MethodInfo("stats_unloaded", PropertyInfo(Variant::INT, "steam_id")));

	// HTTP
	ADD_SIGNAL(MethodInfo("http_request_completed", PropertyInfo(Variant::INT, "cookie_handle"), PropertyInfo(Variant::INT, "context_value"), PropertyInfo(Variant::BOOL, "request_success"), PropertyInfo(Variant::INT, "status_code"), PropertyInfo(Variant::INT, "body_size")));
	ADD_SIGNAL(MethodInfo("http_request_data_received", PropertyInfo(Variant::INT, "cookie_handle"), PropertyInfo(Variant::INT, "context_value"), PropertyInfo(Variant::INT, "offset"), PropertyInfo(Variant::INT, "bytes_received")));
	ADD_SIGNAL(MethodInfo("http_request_headers_received", PropertyInfo(Variant::INT, "cookie_handle"), PropertyInfo(Variant::INT, "context_value")));

	// INVENTORY
	ADD_SIGNAL(MethodInfo("inventory_definition_update", PropertyInfo(Variant::ARRAY, "definitions")));
	ADD_SIGNAL(MethodInfo("inventory_eligible_promo_item", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::BOOL, "cached"), PropertyInfo(Variant::ARRAY, "definitions")));
	ADD_SIGNAL(MethodInfo("inventory_full_update", PropertyInfo(Variant::INT, "inventory_handle")));
	ADD_SIGNAL(MethodInfo("inventory_result_ready", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "inventory_handle")));
	ADD_SIGNAL(MethodInfo("inventory_start_purchase_result", PropertyInfo(Variant::STRING, "result"), PropertyInfo(Variant::INT, "order_id"), PropertyInfo(Variant::INT, "transaction_id")));
	ADD_SIGNAL(MethodInfo("inventory_request_prices_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::STRING, "currency")));

	// NETWORKING
	ADD_SIGNAL(MethodInfo("p2p_session_request", PropertyInfo(Variant::INT, "remote_steam_id")));
	ADD_SIGNAL(MethodInfo("p2p_session_connect_fail", PropertyInfo(Variant::INT, "remote_steam_id"), PropertyInfo(Variant::INT, "session_error")));

	// NETWORKING MESSAGES
	ADD_SIGNAL(MethodInfo("network_messages_session_request", PropertyInfo(Variant::INT, "remote_steam_id")));
	ADD_SIGNAL(MethodInfo("network_messages_session_failed", PropertyInfo(Variant::INT, "reason")));

	// NETWORKING SOCKETS
	ADD_SIGNAL(MethodInfo("network_connection_status_changed", PropertyInfo(Variant::INT, "connect_handle"), PropertyInfo(Variant::DICTIONARY, "connection"), PropertyInfo(Variant::INT, "old_state")));
	ADD_SIGNAL(MethodInfo("network_authentication_status", PropertyInfo(Variant::INT, "available"), PropertyInfo(Variant::STRING, "debug_message")));
	ADD_SIGNAL(MethodInfo("fake_ip_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "remote_fake_steam_id"), PropertyInfo(Variant::STRING, "fake_ip"), PropertyInfo(Variant::ARRAY, "port_list")));

	// NETWORKING UTILS
	ADD_SIGNAL(MethodInfo("relay_network_status", PropertyInfo(Variant::INT, "available"), PropertyInfo(Variant::INT, "ping_measurement"), PropertyInfo(Variant::INT, "available_config"), PropertyInfo(Variant::INT, "available_relay"), PropertyInfo(Variant::STRING, "debug_message")));

	// REMOTE STORAGE
	ADD_SIGNAL(MethodInfo("file_read_async_complete", PropertyInfo(Variant::DICTIONARY, "file_read")));
	ADD_SIGNAL(MethodInfo("file_share_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "handle"), PropertyInfo(Variant::STRING, "name")));
	ADD_SIGNAL(MethodInfo("file_write_async_complete", PropertyInfo(Variant::INT, "result")));
	ADD_SIGNAL(MethodInfo("download_ugc_result", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::DICTIONARY, "download_data")));
	ADD_SIGNAL(MethodInfo("unsubscribe_item", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id")));
	ADD_SIGNAL(MethodInfo("subscribe_item", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id")));
	ADD_SIGNAL(MethodInfo("local_file_changed"));

	// UGC
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
	ADD_SIGNAL(MethodInfo("item_updated", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::BOOL, "need_to_accept_tos")));
	ADD_SIGNAL(MethodInfo("user_favorite_items_list_changed", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "file_id"), PropertyInfo(Variant::BOOL, "was_add_request")));
	ADD_SIGNAL(MethodInfo("workshop_eula_status", PropertyInfo(Variant::INT, "result"), PropertyInfo(Variant::INT, "app_id"), PropertyInfo(Variant::DICTIONARY, "eula_data")));
	ADD_SIGNAL(MethodInfo("user_subscribed_items_list_changed", PropertyInfo(Variant::INT, "app_id")));


	///// PROPERTIES

	ADD_PROPERTY(PropertyInfo(Variant::INT, "inventory_handle"), "set_inventory_handle", "get_inventory_handle");
	ADD_PROPERTY(PropertyInfo(Variant::INT, "inventory_update_handle"), "set_inventory_update_handle", "get_inventory_update_handle");


	///// CONSTANT BINDS

	// STEAM API
	BIND_CONSTANT(ACCOUNT_ID_INVALID);
	BIND_CONSTANT(API_CALL_INVALID);
	BIND_CONSTANT(APP_ID_INVALID);
	BIND_CONSTANT(AUTH_TICKET_INVALID);
	BIND_CONSTANT(DEPOT_ID_INVALID);
	BIND_CONSTANT(GAME_EXTRA_INFO_MAX);
	BIND_CONSTANT(INVALID_BREAKPAD_HANDLE);
	BIND_CONSTANT(QUERY_PORT_ERROR);
	BIND_CONSTANT(QUERY_PORT_NOT_INITIALIZED);
	BIND_CONSTANT(STEAM_ACCOUNT_ID_MASK);
	BIND_CONSTANT(STEAM_ACCOUNT_INSTANCE_MASK);
	BIND_CONSTANT(STEAM_BUFFER_SIZE);
	BIND_CONSTANT(STEAM_LARGE_BUFFER_SIZE);
	BIND_CONSTANT(STEAM_MAX_ERROR_MESSAGE);
	BIND_CONSTANT(STEAM_USER_CONSOLE_INSTANCE);
	BIND_CONSTANT(STEAM_USER_DESKTOP_INSTANCE);
	BIND_CONSTANT(STEAM_USER_WEB_INSTANCE);
	
	// STEAM SERVER
	BIND_CONSTANT(QUERY_PORT_SHARED);

	// HTTP
	BIND_CONSTANT(HTTPCOOKIE_INVALID_HANDLE);
	BIND_CONSTANT(HTTPREQUEST_INVALID_HANDLE);

	// INVENTORY
	BIND_CONSTANT(INVENTORY_RESULT_INVALID);
	BIND_CONSTANT(ITEM_INSTANCE_ID_INVALID);

	// NETWORKING SOCKET
	BIND_CONSTANT(MAX_STEAM_PACKET_SIZE);

	// NETWORKING TYPES
	BIND_CONSTANT(LISTEN_SOCKET_INVALID);
	BIND_CONSTANT(MAX_NETWORKING_ERROR_MESSAGE);
	BIND_CONSTANT(MAX_NETWORKING_PING_LOCATION_STRING);
	BIND_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_ICE_DEFAULT);
	BIND_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_ICE_DISABLE);
	BIND_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_ICE_RELAY);
	BIND_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_ICE_PRIVATE);
	BIND_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_ICE_PUBLIC);
	BIND_CONSTANT(NETWORKING_CONFIG_P2P_TRANSPORT_ICE_ALL);
	BIND_CONSTANT(NETWORKING_CONNECTION_INFO_FLAG_UNAUTHENTICATED);
	BIND_CONSTANT(NETWORKING_CONNECTION_INFO_FLAG_UNENCRYPTED);
	BIND_CONSTANT(NETWORKING_CONNECTION_INFO_FLAG_LOOPBACK_BUFFERS);
	BIND_CONSTANT(NETWORKING_CONNECTION_INFO_FLAG_FAST);
	BIND_CONSTANT(NETWORKING_CONNECTION_INFO_FLAG_RELAYED);
	BIND_CONSTANT(NETWORKING_CONNECTION_INFO_FLAG_DUALWIFI);
	BIND_CONSTANT(NETWORKING_CONNECTION_INVALID);
	BIND_CONSTANT(NETWORKING_MAX_CONNECTION_APP_NAME);
	BIND_CONSTANT(NETWORKING_MAX_CONNECTION_CLOSE_REASON);
	BIND_CONSTANT(NETWORKING_MAX_CONNECTION_DESCRIPTION);
	BIND_CONSTANT(NETWORKING_PING_FAILED);
	BIND_CONSTANT(NETWORKING_PING_UNKNOWN);
	BIND_CONSTANT(NETWORKING_SEND_UNRELIABLE);
	BIND_CONSTANT(NETWORKING_SEND_NO_NAGLE);
	BIND_CONSTANT(NETWORKING_SEND_URELIABLE_NO_NAGLE);
	BIND_CONSTANT(NETWORKING_SEND_NO_DELAY);
	BIND_CONSTANT(NETWORKING_SEND_UNRELIABLE_NO_DELAY);
	BIND_CONSTANT(NETWORKING_SEND_RELIABLE);
	BIND_CONSTANT(NETWORKING_SEND_RELIABLE_NO_NAGLE);
	BIND_CONSTANT(NETWORKING_SEND_USE_CURRENT_THREAD);
	BIND_CONSTANT(NETWORKING_SEND_AUTORESTART_BROKEN_SESSION);

	// UGC
	BIND_CONSTANT(DEVELOPER_METADATA_MAX);
	BIND_CONSTANT(NUM_UGC_RESULTS_PER_PAGE);
	BIND_CONSTANT(UGC_QUERY_HANDLE_INVALID);
	BIND_CONSTANT(UGC_UPDATE_HANDLE_INVALID);


	///// ENUM CONSTANT BINDS

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

	// BeginAuthSessionResult Enums
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_OK);
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_INVALID_TICKET);
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_DUPLICATE_REQUEST);
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_INVALID_VERSION);
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_GAME_MISMATCH);
	BIND_ENUM_CONSTANT(BEGIN_AUTH_SESSION_RESULT_EXPIRED_TICKET);

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

	// IPType Enums
	BIND_ENUM_CONSTANT(IP_TYPE_IPV4);
	BIND_ENUM_CONSTANT(IP_TYPE_IPV6);

	// ItemFlags Enums
	BIND_ENUM_CONSTANT(STEAM_ITEM_NO_TRADE);
	BIND_ENUM_CONSTANT(STEAM_ITEM_REMOVED);
	BIND_ENUM_CONSTANT(STEAM_ITEM_CONSUMED);

	// ItemPreviewType Enums
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_IMAGE);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_YOUTUBE_VIDEO);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_SKETCHFAB);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_ENVIRONMENTMAP_HORIZONTAL_CROSS);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_ENVIRONMENTMAP_LAT_LONG);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_CLIP);
	BIND_ENUM_CONSTANT(ITEM_PREVIEW_TYPE_RESERVED_MAX);

	// ItemState Enums
	BIND_ENUM_CONSTANT(ITEM_STATE_NONE);
	BIND_ENUM_CONSTANT(ITEM_STATE_SUBSCRIBED);
	BIND_ENUM_CONSTANT(ITEM_STATE_LEGACY_ITEM);
	BIND_ENUM_CONSTANT(ITEM_STATE_INSTALLED);
	BIND_ENUM_CONSTANT(ITEM_STATE_NEEDS_UPDATE);
	BIND_ENUM_CONSTANT(ITEM_STATE_DOWNLOADING);
	BIND_ENUM_CONSTANT(ITEM_STATE_DOWNLOAD_PENDING);
	BIND_ENUM_CONSTANT(ITEM_STATE_DISABLED_LOCALLY);

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
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_TYPE_STRING);
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
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_OUT_OF_ORDER_CORRECTION_WINDOW_MICROSECONDS);
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
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_IP_LOCAL_HOST_ALLOW_WITHOUT_AUTH);
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
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_DEV_TICKET);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_FORCE_PROXY_ADDR);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_FAKE_CLUSTER_PING);
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_SDR_CLIENT_LIMIT_PING_PROBES_TO_NEAREST_N);
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
	BIND_ENUM_CONSTANT(NETWORKING_CONFIG_ECN);
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

	// RemoteStoragePlatform Enums
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PLATFORM_NONE);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PLATFORM_WINDOWS);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PLATFORM_OSX);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PLATFORM_PS3);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PLATFORM_LINUX);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PLATFORM_SWITCH);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PLATFORM_ANDROID);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PLATFORM_IOS);
	BIND_ENUM_CONSTANT(REMOTE_STORAGE_PLATFORM_ALL);

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
	BIND_ENUM_CONSTANT(RESULT_ADMINISTRATOR_OK);
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
	BIND_ENUM_CONSTANT(RESULT_NOT_SUPPORTED);
	BIND_ENUM_CONSTANT(RESULT_FAMILY_SIZE_LIMIT_EXCEEDED);
	BIND_ENUM_CONSTANT(RESULT_OFFLINE_APP_CACHE_INVALID);

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
	BIND_ENUM_CONSTANT(UGC_CONTENT_DESCRIPTOR_NUDITY_OR_SEXUAL_CONTENT);
	BIND_ENUM_CONSTANT(UGC_CONTENT_DESCRIPTOR_FREQUENT_VIOLENCE_OR_GORE);
	BIND_ENUM_CONSTANT(UGC_CONTENT_DESCRIPTOR_ADULT_ONLY_SEXUAL_CONTENT);
	BIND_ENUM_CONSTANT(UGC_CONTENT_DESCRIPTOR_GRATUITOUS_SEXUAL_CONTENT);
	BIND_ENUM_CONSTANT(UGC_CONTENT_DESCRIPTOR_ANY_MATURE_CONTENT);

	// UGCMatchingUGCType Enums
	BIND_ENUM_CONSTANT(UGC_MATCHING_UGC_TYPE_ITEMS);
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
	BIND_ENUM_CONSTANT(USER_UGC_LIST_SORT_ORDER_CREATION_ORDER_DESC);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_SORT_ORDER_CREATION_ORDER_ASC);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_SORT_ORDER_TITLE_ASC);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_SORT_ORDER_LAST_UPDATED_DESC);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_SORT_ORDER_SUBSCRIPTION_DATE_DESC);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_SORT_ORDER_VOTE_SCORE_DESC);
	BIND_ENUM_CONSTANT(USER_UGC_LIST_SORT_ORDER_FOR_MODERATION);

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
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_VIDEO);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_SCREENSHOT);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_GAME);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_SOFTWARE);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_CONCEPT);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_WEB_GUIDE);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_INTEGRATED_GUIDE);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_MERCH);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_CONTROLLER_BINDING);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_STEAMWORKS_ACCESS_INVITE);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_STEAM_VIDEO);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_GAME_MANAGED_ITEM);
	BIND_ENUM_CONSTANT(WORKSHOP_FILE_TYPE_CLIP);
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

SteamServer::~SteamServer() {
	if (is_init_success) {
		SteamGameServer_Shutdown();
	}

	inventory_handle = 0;
	inventory_update_handle = 0;
	singleton = NULL;
}
