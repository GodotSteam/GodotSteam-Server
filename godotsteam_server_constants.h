#include "steam/steam_gameserver.h"
#include "steam/steam_api.h"

// Define Steam API constants
// Constants with 'deprecated/': these were listed in the SDK docs but do not exist in the header files; safe to remove probably
// Possibly deprecated or never existed?
#define ACCOUNT_ID_INVALID k_uAccountIdInvalid
#define API_CALL_INVALID k_uAPICallInvalid
#define APP_ID_INVALID k_uAppIdInvalid
#define AUTH_TICKET_INVALID k_HAuthTicketInvalid
#define DEPOT_ID_INVALID k_uDepotIdInvalid
#define GAME_EXTRA_INFO_MAX k_cchGameExtraInfoMax
#define INVALID_BREAKPAD_HANDLE 0 //deprecated?
#define QUERY_PORT_ERROR 0xFFFE //deprecated?
#define QUERY_PORT_NOT_INITIALIZED 0xFFFF //deprecated?
#define STEAM_ACCOUNT_ID_MASK k_unSteamAccountIDMask
#define STEAM_ACCOUNT_INSTANCE_MASK k_unSteamAccountInstanceMask
#define STEAM_BUFFER_SIZE 255 //deprecated?
#define STEAM_LARGE_BUFFER_SIZE 8160 //deprecated?
#define STEAM_MAX_ERROR_MESSAGE 1024
#define STEAM_USER_CONSOLE_INSTANCE 2 //deprecated?
#define STEAM_USER_DESKTOP_INSTANCE k_unSteamUserDefaultInstance
#define STEAM_USER_WEB_INSTANCE 4 //deprecated?

// Define Steam Server API constants
#define QUERY_PORT_SHARED STEAMGAMESERVER_QUERY_PORT_SHARED

// Define HTTP constants
#define HTTPCOOKIE_INVALID_HANDLE INVALID_HTTPCOOKIE_HANDLE
#define HTTPREQUEST_INVALID_HANDLE INVALID_HTTPREQUEST_HANDLE

// Define Inventory constants
#define INVENTORY_RESULT_INVALID k_SteamInventoryResultInvalid
#define ITEM_INSTANCE_ID_INVALID k_SteamItemInstanceIDInvalid

// Define Networking Socket constants
#define MAX_STEAM_PACKET_SIZE k_cbMaxSteamNetworkingSocketsMessageSizeSend

// Define Networking Types constants | Found in steamnetworkingtypes.h
#define LISTEN_SOCKET_INVALID k_HSteamListenSocket_Invalid
#define MAX_NETWORKING_ERROR_MESSAGE k_cchMaxSteamNetworkingErrMsg
#define MAX_NETWORKING_PING_LOCATION_STRING k_cchMaxSteamNetworkingPingLocationString
#define NETWORKING_CONFIG_P2P_TRANSPORT_ICE_DEFAULT k_nSteamNetworkingConfig_P2P_Transport_ICE_Enable_Default
#define NETWORKING_CONFIG_P2P_TRANSPORT_ICE_DISABLE k_nSteamNetworkingConfig_P2P_Transport_ICE_Enable_Disable
#define NETWORKING_CONFIG_P2P_TRANSPORT_ICE_RELAY k_nSteamNetworkingConfig_P2P_Transport_ICE_Enable_Relay
#define NETWORKING_CONFIG_P2P_TRANSPORT_ICE_PRIVATE k_nSteamNetworkingConfig_P2P_Transport_ICE_Enable_Private
#define NETWORKING_CONFIG_P2P_TRANSPORT_ICE_PUBLIC k_nSteamNetworkingConfig_P2P_Transport_ICE_Enable_Public
#define NETWORKING_CONFIG_P2P_TRANSPORT_ICE_ALL k_nSteamNetworkingConfig_P2P_Transport_ICE_Enable_All
#define NETWORKING_CONNECTION_INFO_FLAG_UNAUTHENTICATED k_nSteamNetworkConnectionInfoFlags_Unauthenticated
#define NETWORKING_CONNECTION_INFO_FLAG_UNENCRYPTED k_nSteamNetworkConnectionInfoFlags_Unencrypted
#define NETWORKING_CONNECTION_INFO_FLAG_LOOPBACK_BUFFERS k_nSteamNetworkConnectionInfoFlags_LoopbackBuffers
#define NETWORKING_CONNECTION_INFO_FLAG_FAST k_nSteamNetworkConnectionInfoFlags_Fast
#define NETWORKING_CONNECTION_INFO_FLAG_RELAYED k_nSteamNetworkConnectionInfoFlags_Relayed
#define NETWORKING_CONNECTION_INFO_FLAG_DUALWIFI k_nSteamNetworkConnectionInfoFlags_DualWifi
#define NETWORKING_CONNECTION_INVALID k_HSteamNetConnection_Invalid
#define NETWORKING_MAX_CONNECTION_APP_NAME k_cchSteamNetworkingMaxConnectionAppName
#define NETWORKING_MAX_CONNECTION_CLOSE_REASON k_cchSteamNetworkingMaxConnectionCloseReason
#define NETWORKING_MAX_CONNECTION_DESCRIPTION k_cchSteamNetworkingMaxConnectionDescription
#define NETWORKING_PING_FAILED k_nSteamNetworkingPing_Failed
#define NETWORKING_PING_UNKNOWN k_nSteamNetworkingPing_Unknown
#define NETWORKING_SEND_UNRELIABLE k_nSteamNetworkingSend_Unreliable
#define NETWORKING_SEND_NO_NAGLE k_nSteamNetworkingSend_NoNagle
#define NETWORKING_SEND_URELIABLE_NO_NAGLE k_nSteamNetworkingSend_UnreliableNoNagle
#define NETWORKING_SEND_NO_DELAY k_nSteamNetworkingSend_NoDelay
#define NETWORKING_SEND_UNRELIABLE_NO_DELAY k_nSteamNetworkingSend_UnreliableNoDelay
#define NETWORKING_SEND_RELIABLE k_nSteamNetworkingSend_Reliable
#define NETWORKING_SEND_RELIABLE_NO_NAGLE k_nSteamNetworkingSend_ReliableNoNagle
#define NETWORKING_SEND_USE_CURRENT_THREAD k_nSteamNetworkingSend_UseCurrentThread
#define NETWORKING_SEND_AUTORESTART_BROKEN_SESSION k_nSteamNetworkingSend_AutoRestartBrokenSession

// Define Remote Storage constants
#define ENUMERATE_PUBLISHED_FILES_MAX_RESULTS k_unEnumeratePublishedFilesMaxResults
#define FILE_NAME_MAX k_cchFilenameMax
#define MAX_CLOUD_FILE_CHUNK_SIZE k_unMaxCloudFileChunkSize
#define PUBLISHED_DOCUMENT_CHANGE_DESCRIPTION_MAX k_cchPublishedDocumentChangeDescriptionMax
#define PUBLISHED_DOCUMENT_DESCRIPTION_MAX k_cchPublishedDocumentDescriptionMax
#define PUBLISHED_DOCUMENT_TITLE_MAX k_cchPublishedDocumentTitleMax
#define PUBLISHED_FILE_ID_INVALID k_PublishedFileIdInvalid
#define PUBLISHED_FILE_UPDATE_HANDLE_INVALID k_PublishedFileUpdateHandleInvalid
#define PUBLISHED_FILE_URL_MAX k_cchPublishedFileURLMax
#define TAG_LIST_MAX k_cchTagListMax
#define UGC_FILE_STREAM_HANDLE_INVALID k_UGCFileStreamHandleInvalid
#define UGC_HANDLE_INVALID k_UGCHandleInvalid

// Define UGC constants
#define DEVELOPER_METADATA_MAX k_cchDeveloperMetadataMax
#define NUM_UGC_RESULTS_PER_PAGE kNumUGCResultsPerPage
#define UGC_QUERY_HANDLE_INVALID k_UGCQueryHandleInvalid
#define UGC_UPDATE_HANDLE_INVALID k_UGCUpdateHandleInvalid