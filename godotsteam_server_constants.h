#include "steam/steam_gameserver.h"
#include "steam/steam_api.h"

// Define Steam API constants
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

// Define Networking Message constants
#define NETWORKING_SEND_AUTO_RESTART_BROKEN_SESSION k_nSteamNetworkingSend_AutoRestartBrokenSession
#define NETWORKING_SEND_NO_DELAY k_EP2PSendReliable
#define NETWORKING_SEND_NO_NAGLE k_EP2PSendUnreliableNoDelay
#define NETWORKING_SEND_RELIABLE k_EP2PSendReliableWithBuffering
#define NETWORKING_SEND_UNRELIABLE k_EP2PSendUnreliable

// Define Networking Socket constants
#define MAX_STEAM_PACKET_SIZE k_cbMaxSteamNetworkingSocketsMessageSizeSend

// Define UGC constants
#define DEVELOPER_METADATA_MAX k_cchDeveloperMetadataMax
#define NUM_UGC_RESULTS_PER_PAGE kNumUGCResultsPerPage
#define UGC_QUERY_HANDLE_INVALID k_UGCQueryHandleInvalid
#define UGC_UPDATE_HANDLE_INVALID k_UGCUpdateHandleInvalid