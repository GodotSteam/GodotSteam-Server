#ifndef GODOTSTEAM_SERVER_H
#define GODOTSTEAM_SERVER_H


// Turn off MSVC-only warning about strcpy
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#pragma warning(disable:4996)
#pragma warning(disable:4828)
#endif


// Include INT types header
#include <inttypes.h>

// Include Steamworks Server API header
#include "steam/steam_gameserver.h"
#include "steam/steamnetworkingfakeip.h"

// Include Godot headers
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/classes/global_constants.hpp>
#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/variant/dictionary.hpp>
#include "godot_cpp/variant/packed_string_array.hpp"

// Include GodotSteam headers
#include "godotsteam_server_constants.h"
#include "godotsteam_server_enums.h"

// Include some system headers
#include "map"

using namespace godot;


class SteamServer: public Object {
	GDCLASS(SteamServer, Object);


public:

	static SteamServer* get_singleton();
	SteamServer();
	~SteamServer();


	// STEAMWORKS FUNCTIONS
	// Main
	uint64_t getServerSteamID();
	uint32_t getSteamID32(uint64_t steam_id);
	bool isAnonAccount(uint64_t steam_id);
	bool isAnonUserAccount(uint64_t steam_id);
	bool isChatAccount(uint64_t steam_id);
	bool isClanAccount(uint64_t steam_id);
	bool isConsoleUserAccount(uint64_t steam_id);
	bool isIndividualAccount(uint64_t steam_id);
	bool isLobby(uint64_t steam_id);
	bool isServerSecure();
	bool serverInit(const String &ip, int game_port, int query_port, ServerMode server_mode, const String &version_number);
	Dictionary serverInitEx(const String &ip, int game_port, int query_port, ServerMode server_mode, const String &version_number);
	void serverReleaseCurrentThreadMemory();
	void serverShutdown();

	String get_godotsteam_version() const { return godotsteam_version; }
	int32 get_inventory_handle() const { return inventory_handle; }
	uint64_t get_inventory_update_handle() const { return inventory_update_handle; }
	void set_inventory_handle(int32 new_inventory_handle){ inventory_handle = new_inventory_handle; }
	void set_inventory_update_handle(uint32_t new_inventory_update_handle){ inventory_update_handle = new_inventory_update_handle; }

	// Game Server
	void associateWithClan(uint64_t clan_id);
	uint32 beginAuthSession(PackedByteArray ticket, int ticket_size, uint64_t steam_id);
	void cancelAuthTicket(uint32_t auth_ticket);
	void clearAllKeyValues();
	void computeNewPlayerCompatibility(uint64_t steam_id);
	void endAuthSession(uint64_t steam_id);
	Dictionary getAuthSessionTicket(uint64_t remote_steam_id = 0);
	Dictionary getNextOutgoingPacket();
	Dictionary getPublicIP();
	uint64_t getSteamID();
	Dictionary handleIncomingPacket(int packet, const String &ip, int port);
	bool loggedOn();
	void logOff();
	void logOn(const String &token);
	void logOnAnonymous();
	bool requestUserGroupStatus(uint64_t steam_id, int group_id);
	bool secure();
	void setAdvertiseServerActive(bool active);
	void setBotPlayerCount(int bots);
	void setDedicatedServer(bool dedicated);
	void setGameData(const String &data);
	void setGameDescription(const String &description);
	void setGameTags(const String &tags);
	void setKeyValue(const String &key, const String &value);
	void setMapName(const String &map);
	void setMaxPlayerCount(int players_max);
	void setModDir(const String &mod_directory);
	void setPasswordProtected(bool password_protected);
	void setProduct(const String &product);
	void setRegion(const String &region);
	void setServerName(const String &name);
	void setSpectatorPort(int port);
	void setSpectatorServerName(const String &name);
	int userHasLicenceForApp(uint64_t steam_id, uint32 app_id);
	bool wasRestartRequested();

	// Game Server Stats
	bool clearUserAchievement(uint64_t steam_id, const String &name);
	Dictionary getUserAchievement(uint64_t steam_id, const String &name);
	uint32_t getUserStatInt(uint64_t steam_id, const String &name);
	float getUserStatFloat(uint64_t steam_id, const String &name);
	void requestUserStats(uint64_t steam_id);
	bool setUserAchievement(uint64_t steam_id, const String &name);
	bool setUserStatInt(uint64_t steam_id, const String &name, int32 stat);
	bool setUserStatFloat(uint64_t steam_id, const String &name, float stat);
	void storeUserStats(uint64_t steam_id);
	bool updateUserAvgRateStat(uint64_t steam_id, const String &name, float this_session, double session_length);

	// HTTP
	uint32_t createCookieContainer(bool allow_responses_to_modify);
	uint32_t createHTTPRequest(HTTPMethod request_method, const String &absolute_url);
	bool deferHTTPRequest(uint32 request_handle);
	float getHTTPDownloadProgressPct(uint32 request_handle);
	bool getHTTPRequestWasTimedOut(uint32 request_handle);
	PackedByteArray getHTTPResponseBodyData(uint32 request_handle, uint32 buffer_size);
	uint32 getHTTPResponseBodySize(uint32 request_handle);
	uint32 getHTTPResponseHeaderSize(uint32 request_handle, const String &header_name);
	PackedByteArray getHTTPResponseHeaderValue(uint32 request_handle, const String &header_name, uint32 buffer_size);
	PackedByteArray getHTTPStreamingResponseBodyData(uint32 request_handle, uint32 offset, uint32 buffer_size);
	bool prioritizeHTTPRequest(uint32 request_handle);
	bool releaseCookieContainer(uint32 cookie_handle);
	bool releaseHTTPRequest(uint32 request_handle);
	bool sendHTTPRequest(uint32 request_handle);
	bool sendHTTPRequestAndStreamResponse(uint32 request_handle);
	bool setHTTPCookie(uint32 cookie_handle, const String &host, const String &url, const String &cookie);
	bool setHTTPRequestAbsoluteTimeoutMS(uint32 request_handle, uint32 milliseconds);
	bool setHTTPRequestContextValue(uint32 request_handle, uint64_t context_value);
	bool setHTTPRequestCookieContainer(uint32 request_handle, uint32 cookie_handle);
	bool setHTTPRequestGetOrPostParameter(uint32 request_handle, const String &name, const String &value);
	bool setHTTPRequestHeaderValue(uint32 request_handle, const String &header_name, const String &header_value);
	bool setHTTPRequestNetworkActivityTimeout(uint32 request_handle, uint32 timeout_seconds);
	bool setHTTPRequestRawPostBody(uint32 request_handle, const String &content_type, const String &body);
	bool setHTTPRequestRequiresVerifiedCertificate(uint32 request_handle, bool require_verified_certificate);
	bool setHTTPRequestUserAgentInfo(uint32 request_handle, const String &user_agent_info);

	// Inventory
	int32 addPromoItem(uint32 item);
	int32 addPromoItems(PackedInt64Array items);
	bool checkResultSteamID(uint64_t steam_id_expected, int32 this_inventory_handle = 0);
	int32 consumeItem(uint64_t item_consume, uint32 quantity);
	int32 deserializeResult(PackedByteArray buffer);
	void destroyResult(int32 this_inventory_handle = 0);
	int32 exchangeItems(const PackedInt64Array output_items, const PackedInt32Array output_quantity, const PackedInt64Array input_items, const PackedInt32Array input_quantity);
	int32 generateItems(const PackedInt64Array items, const PackedInt32Array quantity);
	int32 getAllItems();
	String getItemDefinitionProperty(uint32 definition, const String &name);
	int32 getItemsByID(const PackedInt64Array id_array);
	Dictionary getItemPrice(uint32 definition);
	Array getItemsWithPrices();
	String getResultItemProperty(uint32 index, const String &name, int32 this_inventory_handle = 0);
	Array getResultItems(int32 this_inventory_handle = 0);
	Result getResultStatus(int32 this_inventory_handle = 0);
	uint32 getResultTimestamp(int32 this_inventory_handle = 0);
	int32 grantPromoItems();
	bool loadItemDefinitions();
	void requestEligiblePromoItemDefinitionsIDs(uint64_t steam_id);
	void requestPrices();
	PackedByteArray serializeResult(int32 this_inventory_handle = 0);
	void startPurchase(const PackedInt64Array items, const PackedInt32Array quantity);
	int32 transferItemQuantity(uint64_t item_id, uint32 quantity, uint64_t item_destination, bool split);
	int32 triggerItemDrop(uint32 definition);
	void startUpdateProperties();
	int32 submitUpdateProperties(uint64_t this_inventory_update_handle = 0);
	bool removeProperty(uint64_t item_id, const String &name, uint64_t this_inventory_update_handle = 0);
	bool setPropertyString(uint64_t item_id, const String &name, const String &value, uint64_t this_inventory_update_handle = 0);
	bool setPropertyBool(uint64_t item_id, const String &name, bool value, uint64_t this_inventory_update_handle = 0);
	bool setPropertyInt(uint64_t item_id, const String &name, uint64_t value, uint64_t this_inventory_update_handle = 0);
	bool setPropertyFloat(uint64_t item_id, const String &name, float value, uint64_t this_inventory_update_handle = 0);

	// Networking
	bool acceptP2PSessionWithUser(uint64_t remote_steam_id);
	bool allowP2PPacketRelay(bool allow);
	bool closeP2PChannelWithUser(uint64_t remote_steam_id, int channel);
	bool closeP2PSessionWithUser(uint64_t remote_steam_id);
	Dictionary getP2PSessionState(uint64_t remote_steam_id);
	uint32_t getAvailableP2PPacketSize(int channel = 0);
	Dictionary readP2PPacket(uint32_t packet, int channel = 0);
	bool sendP2PPacket(uint64_t remote_steam_id, const PackedByteArray data, P2PSend send_type, int channel = 0);

	// Networking Messages
	bool acceptSessionWithUser(uint64_t remote_steam_id);
	bool closeChannelWithUser(uint64_t remote_steam_id, int channel);
	bool closeSessionWithUser(uint64_t remote_steam_id);
	Dictionary getSessionConnectionInfo(uint64_t remote_steam_id, bool get_connection, bool get_status);
	Array receiveMessagesOnChannel(int channel, int max_messages);
	int sendMessageToUser(uint64_t remote_steam_id, const PackedByteArray data, int flags, int channel);
	
	// Networking Sockets
	int acceptConnection(uint32 connection_handle);
	bool beginAsyncRequestFakeIP(int num_ports);
	bool closeConnection(uint32 peer, int reason, const String &debug_message, bool linger);
	bool closeListenSocket(uint32 socket);
	int configureConnectionLanes(uint32 connection, int lanes, Array priorities, Array weights);
	uint32 connectP2P(uint64_t remote_steam_id, int virtual_port, Dictionary config_options);
	uint32 connectByIPAddress(const String &ip_address_with_port, Dictionary config_options);
	uint32 connectToHostedDedicatedServer(uint64_t remote_steam_id, int virtual_port, Dictionary config_options);
	void createFakeUDPPort(int fake_server_port);
	uint32 createHostedDedicatedServerListenSocket(int virtual_port, Dictionary config_options);
	uint32 createListenSocketIP(const String &ip_address, Dictionary config_options);
	uint32 createListenSocketP2P(int virtual_port, Dictionary config_options);
	uint32 createListenSocketP2PFakeIP(int fake_port, Dictionary config_options);
	uint32 createPollGroup();
	Dictionary createSocketPair(bool loopback, uint64_t remote_steam_id1, uint64_t remote_steam_id2);
	bool destroyPollGroup(uint32 poll_group);
//	int findRelayAuthTicketForServer(int port);	<------ Uses datagram relay structs which were removed from base SDK
	int flushMessagesOnConnection(uint32 connection_handle);
	NetworkingAvailability getAuthenticationStatus();
	Dictionary getCertificateRequest();
	Dictionary getConnectionInfo(uint32 connection_handle);
	String getConnectionName(uint32 peer);
	Dictionary getConnectionRealTimeStatus(uint32 connection_handle, int lanes, bool get_status = true);
	uint64_t getConnectionUserData(uint32 peer);
	Dictionary getDetailedConnectionStatus(uint32 connection_handle);
	Dictionary getFakeIP(int first_port = 0);
//	int getGameCoordinatorServerLogin(const String &app_data);	<------ Uses datagram relay structs which were removed from base SDK
//	int getHostedDedicatedServerAddress();	<------ Uses datagram relay structs which were removed from base SDK
	uint32 getHostedDedicatedServerPOPId();
	int getHostedDedicatedServerPort();
	String getListenSocketAddress(uint32 socket, bool with_port = true);
	Dictionary getRemoteFakeIPForConnection(uint32 connection);
	NetworkingAvailability initAuthentication();
	Array receiveMessagesOnConnection(uint32 connection, int max_messages);
	Array receiveMessagesOnPollGroup(uint32 poll_group, int max_messages);
//	Dictionary receivedRelayAuthTicket();	<------ Uses datagram relay structs which were removed from base SDK
	void resetIdentity(uint64_t remote_steam_id);
	void runNetworkingCallbacks();
//	Array sendMessages(Array messages, uint32 connection_handle, int flags);	<------ Currently does not compile on Windows but does on Linux
	Dictionary sendMessageToConnection(uint32 connection_handle, const PackedByteArray data, int flags);
	Dictionary setCertificate(const PackedByteArray &certificate);
	bool setConnectionPollGroup(uint32 connection_handle, uint32 poll_group);
	void setConnectionName(uint32 peer, const String &name);

	// Networking Utils
	bool checkPingDataUpToDate(float max_age_in_seconds);
	String convertPingLocationToString(PackedByteArray location);
	int estimatePingTimeBetweenTwoLocations(PackedByteArray location1, PackedByteArray location2);
	int estimatePingTimeFromLocalHost(PackedByteArray location);
	Dictionary getConfigValue(NetworkingConfigValue config_value, NetworkingConfigScope scope_type, uint32_t connection_handle);
	Dictionary getConfigValueInfo(NetworkingConfigValue config_value);
	int getDirectPingToPOP(uint32 pop_id);
	Dictionary getLocalPingLocation();
	uint64_t getLocalTimestamp();
	Dictionary getPingToDataCenter(uint32 pop_id);
	int getPOPCount();
	Array getPOPList();
	NetworkingAvailability getRelayNetworkStatus();
	void initRelayNetworkAccess();
	Dictionary parsePingLocationString(const String &location_string);
	bool setConnectionConfigValueFloat(uint32 connection, NetworkingConfigValue config, float value);
	bool setConnectionConfigValueInt32(uint32 connection, NetworkingConfigValue config, int32 value);
	bool setConnectionConfigValueString(uint32 connection, NetworkingConfigValue config, const String &value);
//		bool setConfigValue(NetworkingConfigValue setting, NetworkingConfigScope scope_type, uint32_t connection_handle, NetworkingConfigDataType data_type, auto value);
	bool setGlobalConfigValueFloat(NetworkingConfigValue config, float value);
	bool setGlobalConfigValueInt32(NetworkingConfigValue config, int32 value);
	bool setGlobalConfigValueString(NetworkingConfigValue config, const String &value);

	// UGC
	void addAppDependency(uint64_t published_file_id, uint32_t app_id);
	bool addContentDescriptor(uint64_t update_handle, int descriptor_id);
	void addDependency(uint64_t published_file_id, uint64_t child_published_file_id);
	bool addExcludedTag(uint64_t query_handle, const String &tag_name);
	bool addItemKeyValueTag(uint64_t query_handle, const String &key, const String &value);
	bool addItemPreviewFile(uint64_t query_handle, const String &preview_file, ItemPreviewType type);
	bool addItemPreviewVideo(uint64_t query_handle, const String &video_id);
	void addItemToFavorites(uint32_t app_id, uint64_t published_file_id);
	bool addRequiredKeyValueTag(uint64_t query_handle, const String &key, const String &value);
	bool addRequiredTag(uint64_t query_handle, const String &tag_name);
	bool addRequiredTagGroup(uint64_t query_handle, Array tag_array);
	bool initWorkshopForGameServer(uint32_t workshop_depot_id, String folder);
	void createItem(uint32 app_id, WorkshopFileType file_type);
	uint64_t createQueryAllUGCRequest(UGCQuery query_type, UGCMatchingUGCType matching_type, uint32_t creator_id, uint32_t consumer_id, uint32 page);
	uint64_t createQueryUGCDetailsRequest(Array published_file_id);
	uint64_t createQueryUserUGCRequest(uint64_t steam_id, UserUGCList list_type, UGCMatchingUGCType matching_ugc_type, UserUGCListSortOrder sort_order, uint32_t creator_id, uint32_t consumer_id, uint32 page);
	void deleteItem(uint64_t published_file_id);
	bool downloadItem(uint64_t published_file_id, bool high_priority);
	Dictionary getItemDownloadInfo(uint64_t published_file_id);
	Dictionary getItemInstallInfo(uint64_t published_file_id);
	uint32 getItemState(uint64_t published_file_id);
	Dictionary getItemUpdateProgress(uint64_t update_handle);
	uint32 getNumSubscribedItems();
	uint32 getNumSupportedGameVersions(uint64_t query_handle, uint32 index);
	Dictionary getQueryUGCAdditionalPreview(uint64_t query_handle, uint32 index, uint32 preview_index);
	Dictionary getQueryUGCChildren(uint64_t query_handle, uint32 index, uint32_t child_count);
	Dictionary getQueryUGCContentDescriptors(uint64_t query_handle, uint32 index, uint32_t max_entries);
	Dictionary getQueryUGCKeyValueTag(uint64_t query_handle, uint32 index, uint32 key_value_tag_index);
	String getQueryUGCMetadata(uint64_t query_handle, uint32 index);
	uint32 getQueryUGCNumAdditionalPreviews(uint64_t query_handle, uint32 index);
	uint32 getQueryUGCNumKeyValueTags(uint64_t query_handle, uint32 index);
	uint32 getQueryUGCNumTags(uint64_t query_handle, uint32 index);
	String getQueryUGCPreviewURL(uint64_t query_handle, uint32 index);
	Dictionary getQueryUGCResult(uint64_t query_handle, uint32 index);
	Dictionary getQueryUGCStatistic(uint64_t query_handle, uint32 index, ItemStatistic stat_type);
	String getQueryUGCTag(uint64_t query_handle, uint32 index, uint32 tag_index);
	String getQueryUGCTagDisplayName(uint64_t query_handle, uint32 index, uint32 tag_index);
	Array getSubscribedItems();
	Dictionary getSupportedGameVersionData(uint64_t query_handle, uint32 index, uint32 version_index);
	Array getUserContentDescriptorPreferences(uint32 max_entries);
	void getUserItemVote(uint64_t published_file_id);
	bool releaseQueryUGCRequest(uint64_t query_handle);
	void removeAppDependency(uint64_t published_file_id, uint32_t app_id);
	bool removeContentDescriptor(uint64_t update_handle, int descriptor_id);
	void removeDependency(uint64_t published_file_id, uint64_t child_published_file_id);
	void removeItemFromFavorites(uint32_t app_id, uint64_t published_file_id);
	bool removeItemKeyValueTags(uint64_t update_handle, const String &key);
	bool removeItemPreview(uint64_t update_handle, uint32 index);
	void sendQueryUGCRequest(uint64_t update_handle);
	bool setAdminQuery(uint64_t update_handle, bool admin_query);
	bool setAllowCachedResponse(uint64_t update_handle, uint32 max_age_seconds);
	bool setCloudFileNameFilter(uint64_t update_handle, const String &match_cloud_filename);
	bool setItemContent(uint64_t update_handle, const String &content_folder);
	bool setItemDescription(uint64_t update_handle, const String &description);
	bool setItemMetadata(uint64_t update_handle, const String &ugc_metadata);
	bool setItemPreview(uint64_t update_handle, const String &preview_file);
	bool setItemTags(uint64_t update_handle, Array tag_array, bool allow_admin_tags = false);
	bool setItemTitle(uint64_t update_handle, const String &title);
	bool setItemUpdateLanguage(uint64_t update_handle, const String &language);
	bool setItemVisibility(uint64_t update_handle, RemoteStoragePublishedFileVisibility visibility);
	bool setLanguage(uint64_t query_handle, const String &language);
	bool setMatchAnyTag(uint64_t query_handle, bool match_any_tag);
	bool setRankedByTrendDays(uint64_t query_handle, uint32 days);
	bool setRequiredGameVersions(uint64_t query_handle, String game_branch_min, String game_branch_max);
	bool setReturnAdditionalPreviews(uint64_t query_handle, bool return_additional_previews);
	bool setReturnChildren(uint64_t query_handle, bool return_children);
	bool setReturnKeyValueTags(uint64_t query_handle, bool return_key_value_tags);
	bool setReturnLongDescription(uint64_t query_handle, bool return_long_description);
	bool setReturnMetadata(uint64_t query_handle, bool return_metadata);
	bool setReturnOnlyIDs(uint64_t query_handle, bool return_only_ids);
	bool setReturnPlaytimeStats(uint64_t query_handle, uint32 days);
	bool setReturnTotalOnly(uint64_t query_handle, bool return_total_only);
	bool setSearchText(uint64_t query_handle, const String &search_text);
	void setUserItemVote(uint64_t published_file_id, bool vote_up);
	uint64_t startItemUpdate(uint32_t app_id, uint64_t file_id);
	void startPlaytimeTracking(Array published_file_ids);
	void stopPlaytimeTracking(Array published_file_ids);
	void stopPlaytimeTrackingForAllItems();
	void getAppDependencies(uint64_t published_file_id);
	void submitItemUpdate(uint64_t update_handle, const String &change_note);
	void subscribeItem(uint64_t published_file_id);
	void suspendDownloads(bool suspend);
	void unsubscribeItem(uint64_t published_file_id);
	bool updateItemPreviewFile(uint64_t update_handle, uint32 index, const String &preview_file);
	bool updateItemPreviewVideo(uint64_t update_handle, uint32 index, const String &video_id);
	bool showWorkshopEULA();
	void getWorkshopEULAStatus();
	bool setTimeCreatedDateRange(uint64_t update_handle, uint32 start, uint32 end);
	bool setTimeUpdatedDateRange(uint64_t update_handle, uint32 start, uint32 end);


	// PROPERTIES
	// Inventory
	SteamInventoryResult_t inventory_handle = 0;
	SteamInventoryUpdateHandle_t inventory_update_handle = 0;


protected:
	static void _bind_methods();
	static SteamServer* singleton;


private:
	// Main
	String godotsteam_version = "4.4";
	bool is_init_success;

	const SteamNetworkingConfigValue_t *convert_config_options(Dictionary config_options);
	CSteamID createSteamID(uint64_t steam_id, AccountType account_type = AccountType(-1));
	SteamNetworkingIdentity getIdentityFromSteamID(uint64_t steam_id);
	uint32 getIPFromSteamIP(SteamNetworkingIPAddr this_address);
	uint32 getIPFromString(String ip_string);
	uint64_t getSteamIDFromIdentity(SteamNetworkingIdentity this_identity);
	SteamNetworkingIPAddr getSteamIPFromInt(uint32 ip_integer);
	SteamNetworkingIPAddr getSteamIPFromString(String ip_string);
	String getStringFromIP(uint32 ip_address);
	String getStringFromSteamIP(SteamNetworkingIPAddr this_address);

	// Networking Sockets
	uint64_t networking_microseconds = 0;
//	SteamDatagramHostedAddress hosted_address;
//	PackedByteArray routing_blob;
//	SteamDatagramRelayAuthTicket relay_auth_ticket;

	// Run the Steamworks server API callbacks
	void run_callbacks(){
		SteamGameServer_RunCallbacks();
	}


	// STEAM SERVER CALLBACKS
	// Game Server
	STEAM_GAMESERVER_CALLBACK(SteamServer, server_connect_failure, SteamServerConnectFailure_t, callbackServerConnectFailure);
	STEAM_GAMESERVER_CALLBACK(SteamServer, server_connected, SteamServersConnected_t, callbackServerConnected);
	STEAM_GAMESERVER_CALLBACK(SteamServer, server_disconnected, SteamServersDisconnected_t, callbackServerDisconnected);
	STEAM_GAMESERVER_CALLBACK(SteamServer, client_approved, GSClientApprove_t, callbackClientApproved);
	STEAM_GAMESERVER_CALLBACK(SteamServer, client_denied, GSClientDeny_t, callbackClientDenied);
	STEAM_GAMESERVER_CALLBACK(SteamServer, client_kick, GSClientKick_t, callbackClientKicked);
	STEAM_GAMESERVER_CALLBACK(SteamServer, policy_response, GSPolicyResponse_t, callbackPolicyResponse);
	STEAM_GAMESERVER_CALLBACK(SteamServer, client_group_status, GSClientGroupStatus_t, callbackClientGroupStatus);
	STEAM_GAMESERVER_CALLBACK(SteamServer, associate_clan, AssociateWithClanResult_t, callbackAssociateClan);
	STEAM_GAMESERVER_CALLBACK(SteamServer, player_compat, ComputeNewPlayerCompatibilityResult_t, callbackPlayerCompat);

	// Game Server Stats
	STEAM_GAMESERVER_CALLBACK(SteamServer, stats_stored, GSStatsStored_t, callbackStatsStored);
	STEAM_GAMESERVER_CALLBACK(SteamServer, stats_unloaded, GSStatsUnloaded_t, callbackStatsUnloaded);

	// HTTP
	STEAM_GAMESERVER_CALLBACK(SteamServer, http_request_completed, HTTPRequestCompleted_t, callbackHTTPRequestCompleted);
	STEAM_GAMESERVER_CALLBACK(SteamServer, http_request_data_received, HTTPRequestDataReceived_t, callbackHTTPRequestDataReceived);
	STEAM_GAMESERVER_CALLBACK(SteamServer, http_request_headers_received, HTTPRequestHeadersReceived_t, callbackHTTPRequestHeadersReceived);

	// Inventory
	STEAM_GAMESERVER_CALLBACK(SteamServer, inventory_definition_update, SteamInventoryDefinitionUpdate_t, callbackInventoryDefinitionUpdate);
	STEAM_GAMESERVER_CALLBACK(SteamServer, inventory_full_update, SteamInventoryFullUpdate_t, callbackInventoryFullUpdate);
	STEAM_GAMESERVER_CALLBACK(SteamServer, inventory_result_ready, SteamInventoryResultReady_t, callbackInventoryResultReady);

	// Networking
	STEAM_GAMESERVER_CALLBACK(SteamServer, p2p_session_connect_fail, P2PSessionConnectFail_t, callbackP2PSessionConnectFail);
	STEAM_GAMESERVER_CALLBACK(SteamServer, p2p_session_request, P2PSessionRequest_t, callbackP2PSessionRequest);

	// Networking Messages
	STEAM_GAMESERVER_CALLBACK(SteamServer, network_messages_session_request, SteamNetworkingMessagesSessionRequest_t, callbackNetworkMessagesSessionRequest);
	STEAM_GAMESERVER_CALLBACK(SteamServer, network_messages_session_failed, SteamNetworkingMessagesSessionFailed_t, callbackNetworkMessagesSessionFailed);

	// Networking Sockets
	STEAM_GAMESERVER_CALLBACK(SteamServer, network_connection_status_changed, SteamNetConnectionStatusChangedCallback_t, callbackNetworkConnectionStatusChanged);
	STEAM_GAMESERVER_CALLBACK(SteamServer, network_authentication_status, SteamNetAuthenticationStatus_t, callbackNetworkAuthenticationStatus);
	STEAM_GAMESERVER_CALLBACK(SteamServer, fake_ip_result, SteamNetworkingFakeIPResult_t, callbackNetworkingFakeIPResult);

	// Networking Utils
	STEAM_GAMESERVER_CALLBACK(SteamServer, relay_network_status, SteamRelayNetworkStatus_t, callbackRelayNetworkStatus);

	// Remote Storage
	STEAM_GAMESERVER_CALLBACK(SteamServer, local_file_changed, RemoteStorageLocalFileChange_t, callbackLocalFileChanged);

	// UGC
	STEAM_GAMESERVER_CALLBACK(SteamServer, item_downloaded, DownloadItemResult_t, callbackItemDownloaded);
	STEAM_GAMESERVER_CALLBACK(SteamServer, item_installed, ItemInstalled_t, callbackItemInstalled);
	STEAM_GAMESERVER_CALLBACK(SteamServer, user_subscribed_items_list_changed, UserSubscribedItemsListChanged_t, callbackUserSubscribedItemsListChanged);


	// STEAM CALL RESULTS
	// Game Server Stats
	CCallResult<SteamServer, GSStatsReceived_t> callResultStatReceived;
	void stats_received(GSStatsReceived_t *call_data, bool io_failure);

	// Inventory
	CCallResult<SteamServer, SteamInventoryEligiblePromoItemDefIDs_t> callResultEligiblePromoItemDefIDs;
	void inventory_eligible_promo_item(SteamInventoryEligiblePromoItemDefIDs_t *call_data, bool io_failure);
	CCallResult<SteamServer, SteamInventoryRequestPricesResult_t> callResultRequestPrices;
	void inventory_request_prices_result(SteamInventoryRequestPricesResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, SteamInventoryStartPurchaseResult_t> callResultStartPurchase;
	void inventory_start_purchase_result(SteamInventoryStartPurchaseResult_t *call_data, bool io_failure);

	// Remote Storage
	CCallResult<SteamServer, RemoteStorageFileReadAsyncComplete_t> callResultFileReadAsyncComplete;
	void file_read_async_complete(RemoteStorageFileReadAsyncComplete_t *call_data, bool io_failure);
	CCallResult<SteamServer, RemoteStorageFileShareResult_t> callResultFileShareResult;
	void file_share_result(RemoteStorageFileShareResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, RemoteStorageFileWriteAsyncComplete_t> callResultFileWriteAsyncComplete;
	void file_write_async_complete(RemoteStorageFileWriteAsyncComplete_t *call_data, bool io_failure);
	CCallResult<SteamServer, RemoteStorageDownloadUGCResult_t> callResultDownloadUGCResult;
	void download_ugc_result(RemoteStorageDownloadUGCResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, RemoteStorageUnsubscribePublishedFileResult_t> callResultUnsubscribeItem;
	void unsubscribe_item(RemoteStorageUnsubscribePublishedFileResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, RemoteStorageSubscribePublishedFileResult_t> callResultSubscribeItem;
	void subscribe_item(RemoteStorageSubscribePublishedFileResult_t *call_data, bool io_failure);

	// UGC
	CCallResult<SteamServer, AddAppDependencyResult_t> callResultAddAppDependency;
	void add_app_dependency_result(AddAppDependencyResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, AddUGCDependencyResult_t> callResultAddUGCDependency;
	void add_ugc_dependency_result(AddUGCDependencyResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, CreateItemResult_t> callResultItemCreate;
	void item_created(CreateItemResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, GetAppDependenciesResult_t> callResultGetAppDependencies;
	void get_app_dependencies_result(GetAppDependenciesResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, DeleteItemResult_t> callResultDeleteItem;
	void item_deleted(DeleteItemResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, GetUserItemVoteResult_t> callResultGetUserItemVote;
	void get_item_vote_result(GetUserItemVoteResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, RemoveAppDependencyResult_t> callResultRemoveAppDependency;
	void remove_app_dependency_result(RemoveAppDependencyResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, RemoveUGCDependencyResult_t> callResultRemoveUGCDependency;
	void remove_ugc_dependency_result(RemoveUGCDependencyResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, SetUserItemVoteResult_t> callResultSetUserItemVote;
	void set_user_item_vote(SetUserItemVoteResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, StartPlaytimeTrackingResult_t> callResultStartPlaytimeTracking;
	void start_playtime_tracking(StartPlaytimeTrackingResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, SteamUGCQueryCompleted_t> callResultUGCQueryCompleted;
	void ugc_query_completed(SteamUGCQueryCompleted_t *call_data, bool io_failure);
	CCallResult<SteamServer, StopPlaytimeTrackingResult_t> callResultStopPlaytimeTracking;
	void stop_playtime_tracking(StopPlaytimeTrackingResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, SubmitItemUpdateResult_t> callResultItemUpdate;
	void item_updated(SubmitItemUpdateResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, UserFavoriteItemsListChanged_t> callResultFavoriteItemListChanged;
	void user_favorite_items_list_changed(UserFavoriteItemsListChanged_t *call_data, bool io_failure);
	CCallResult<SteamServer, WorkshopEULAStatus_t> callResultWorkshopEULAStatus;
	void workshop_eula_status(WorkshopEULAStatus_t *call_data, bool io_failure);
};


VARIANT_ENUM_CAST(AccountType);
VARIANT_ENUM_CAST(AuthSessionResponse);

VARIANT_ENUM_CAST(BeginAuthSessionResult);

VARIANT_ENUM_CAST(DenyReason);

VARIANT_ENUM_CAST(FilePathType);

VARIANT_ENUM_CAST(GameIDType);

VARIANT_ENUM_CAST(HTTPMethod);
VARIANT_ENUM_CAST(HTTPStatusCode);

VARIANT_ENUM_CAST(IPType);
VARIANT_BITFIELD_CAST(ItemFlags);
VARIANT_ENUM_CAST(ItemPreviewType);
VARIANT_BITFIELD_CAST(ItemState);
VARIANT_ENUM_CAST(ItemStatistic);
VARIANT_ENUM_CAST(ItemUpdateStatus);

VARIANT_ENUM_CAST(LocalFileChange);

VARIANT_ENUM_CAST(NetworkingAvailability);
VARIANT_ENUM_CAST(NetworkingConfigDataType);
VARIANT_ENUM_CAST(NetworkingConfigScope);
VARIANT_ENUM_CAST(NetworkingConfigValue);
VARIANT_ENUM_CAST(NetworkingConnectionEnd);
VARIANT_ENUM_CAST(NetworkingConnectionState);
VARIANT_ENUM_CAST(NetworkingFakeIPType);
VARIANT_ENUM_CAST(NetworkingGetConfigValueResult);
VARIANT_ENUM_CAST(NetworkingIdentityType);
VARIANT_ENUM_CAST(NetworkingSocketsDebugOutputType);

VARIANT_ENUM_CAST(P2PSend);
VARIANT_ENUM_CAST(P2PSessionError);

VARIANT_BITFIELD_CAST(RemoteStoragePlatform);
VARIANT_ENUM_CAST(RemoteStoragePublishedFileVisibility);
VARIANT_ENUM_CAST(Result);

VARIANT_ENUM_CAST(ServerMode);
VARIANT_ENUM_CAST(SocketConnectionType);
VARIANT_ENUM_CAST(SocketState);
VARIANT_ENUM_CAST(SteamAPIInitResult);

VARIANT_ENUM_CAST(UGCContentDescriptorID);
VARIANT_ENUM_CAST(UGCMatchingUGCType);
VARIANT_ENUM_CAST(UGCQuery);
VARIANT_ENUM_CAST(UGCReadAction);
VARIANT_ENUM_CAST(Universe);
VARIANT_ENUM_CAST(UserUGCList);
VARIANT_ENUM_CAST(UserUGCListSortOrder);

VARIANT_ENUM_CAST(WorkshopEnumerationType);
VARIANT_ENUM_CAST(WorkshopFileAction);
VARIANT_ENUM_CAST(WorkshopFileType);
VARIANT_ENUM_CAST(WorkshopVideoProvider);
VARIANT_ENUM_CAST(WorkshopVote);


#endif // GODOTSTEAM_SERVER_H