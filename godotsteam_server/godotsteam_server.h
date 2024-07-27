#ifndef GODOTSTEAM_SERVER_H
#define GODOTSTEAM_SERVER_H


// SILENCE STEAMWORKS WARNINGS
/////////////////////////////////////////////////
//
// Turn off MSVC-only warning about strcpy
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS 1
#pragma warning(disable:4996)
#pragma warning(disable:4828)
#endif


// INCLUDE HEADERS
/////////////////////////////////////////////////
//
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

// Include some system headers
#include "map"

using namespace godot;


class SteamServer: public Object {
	GDCLASS(SteamServer, Object);

	
public:

	static SteamServer *get_singleton();
	SteamServer();
	~SteamServer();


	// STEAMWORKS API ENUMS
	/////////////////////////////////////////
	//
	enum AccountType {
		// Found in steamclientpublic.h
		ACCOUNT_TYPE_INVALID = k_EAccountTypeInvalid,
		ACCOUNT_TYPE_INDIVIDUAL = k_EAccountTypeIndividual,
		ACCOUNT_TYPE_MULTISEAT = k_EAccountTypeMultiseat,
		ACCOUNT_TYPE_GAME_SERVER = k_EAccountTypeGameServer,
		ACCOUNT_TYPE_ANON_GAME_SERVER = k_EAccountTypeAnonGameServer,
		ACCOUNT_TYPE_PENDING = k_EAccountTypePending,
		ACCOUNT_TYPE_CONTENT_SERVER = k_EAccountTypeContentServer,
		ACCOUNT_TYPE_CLAN = k_EAccountTypeClan,
		ACCOUNT_TYPE_CHAT = k_EAccountTypeChat,
		ACCOUNT_TYPE_CONSOLE_USER = k_EAccountTypeConsoleUser,
		ACCOUNT_TYPE_ANON_USER = k_EAccountTypeAnonUser,
		ACCOUNT_TYPE_MAX = k_EAccountTypeMax
	};
	enum AuthSessionResponse {
		// Found in steamclientpublic.h
		AUTH_SESSION_RESPONSE_OK = k_EAuthSessionResponseOK,
		AUTH_SESSION_RESPONSE_USER_NOT_CONNECTED_TO_STEAM = k_EAuthSessionResponseUserNotConnectedToSteam,
		AUTH_SESSION_RESPONSE_NO_LICENSE_OR_EXPIRED = k_EAuthSessionResponseNoLicenseOrExpired,
		AUTH_SESSION_RESPONSE_VAC_BANNED = k_EAuthSessionResponseVACBanned,
		AUTH_SESSION_RESPONSE_LOGGED_IN_ELSEWHERE = k_EAuthSessionResponseLoggedInElseWhere,
		AUTH_SESSION_RESPONSE_VAC_CHECK_TIMED_OUT = k_EAuthSessionResponseVACCheckTimedOut,
		AUTH_SESSION_RESPONSE_AUTH_TICKET_CANCELED = k_EAuthSessionResponseAuthTicketCanceled,
		AUTH_SESSION_RESPONSE_AUTH_TICKET_INVALID_ALREADY_USED = k_EAuthSessionResponseAuthTicketInvalidAlreadyUsed,
		AUTH_SESSION_RESPONSE_AUTH_TICKET_INVALID = k_EAuthSessionResponseAuthTicketInvalid,
		AUTH_SESSION_RESPONSE_PUBLISHER_ISSUED_BAN = k_EAuthSessionResponsePublisherIssuedBan,
		AUTH_SESSION_RESPONSE_AUTH_TICKET_NETWORK_IDENTITY_FAILURE = k_EAuthSessionResponseAuthTicketNetworkIdentityFailure
	};
	enum BeginAuthSessionResult {
		// Found in steamclientpublic.h
		BEGIN_AUTH_SESSION_RESULT_OK = k_EBeginAuthSessionResultOK,
		BEGIN_AUTH_SESSION_RESULT_INVALID_TICKET = k_EBeginAuthSessionResultInvalidTicket,
		BEGIN_AUTH_SESSION_RESULT_DUPLICATE_REQUEST = k_EBeginAuthSessionResultDuplicateRequest,
		BEGIN_AUTH_SESSION_RESULT_INVALID_VERSION = k_EBeginAuthSessionResultInvalidVersion,
		BEGIN_AUTH_SESSION_RESULT_GAME_MISMATCH = k_EBeginAuthSessionResultGameMismatch,
		BEGIN_AUTH_SESSION_RESULT_EXPIRED_TICKET = k_EBeginAuthSessionResultExpiredTicket
	};
	enum DenyReason {
		// Found in steamclientpublic.h
		DENY_INVALID = k_EDenyInvalid,
		DENY_INVALID_VERSION = k_EDenyInvalidVersion,
		DENY_GENERIC = k_EDenyGeneric,
		DENY_NOT_LOGGED_ON = k_EDenyNotLoggedOn,
		DENY_NO_LICENSE = k_EDenyNoLicense,
		DENY_CHEATER = k_EDenyCheater,
		DENY_LOGGED_IN_ELSEWHERE = k_EDenyLoggedInElseWhere,
		DENY_UNKNOWN_TEXT = k_EDenyUnknownText,
		DENY_INCOMPATIBLE_ANTI_CHEAT = k_EDenyIncompatibleAnticheat,
		DENY_MEMORY_CORRUPTION = k_EDenyMemoryCorruption,
		DENY_INCOMPATIBLE_SOFTWARE = k_EDenyIncompatibleSoftware,
		DENY_STEAM_CONNECTION_LOST = k_EDenySteamConnectionLost,
		DENY_STEAM_CONNECTION_ERROR = k_EDenySteamConnectionError,
		DENY_STEAM_RESPONSE_TIMED_OUT = k_EDenySteamResponseTimedOut,
		DENY_STEAM_VALIDATION_STALLED = k_EDenySteamValidationStalled,
		DENY_STEAM_OWNER_LEFT_GUEST_USER = k_EDenySteamOwnerLeftGuestUser
	};
	enum GameIDType {
		GAME_TYPE_APP = CGameID::k_EGameIDTypeApp,
		GAME_TYPE_GAME_MOD = CGameID::k_EGameIDTypeGameMod,
		GAME_TYPE_SHORTCUT = CGameID::k_EGameIDTypeShortcut,
		GAME_TYPE_P2P = CGameID::k_EGameIDTypeP2P
	};
	enum IPType {
		IP_TYPE_IPV4 = k_ESteamIPTypeIPv4,
		IP_TYPE_IPV6 = k_ESteamIPTypeIPv6
	};
	enum Result {
		// Found in steamclientpublic.h
		RESULT_NONE = k_EResultNone,
		RESULT_OK = k_EResultOK,
		RESULT_FAIL = k_EResultFail,
		RESULT_NO_CONNECTION = k_EResultNoConnection,
		RESULT_INVALID_PASSWORD = k_EResultInvalidPassword,
		RESULT_LOGGED_IN_ELSEWHERE = k_EResultLoggedInElsewhere,
		RESULT_INVALID_PROTOCOL_VER = k_EResultInvalidProtocolVer,
		RESULT_INVALID_PARAM = k_EResultInvalidParam,
		RESULT_FILE_NOT_FOUND = k_EResultFileNotFound,
		RESULT_BUSY = k_EResultBusy,
		RESULT_INVALID_STATE = k_EResultInvalidState,
		RESULT_INVALID_NAME = k_EResultInvalidName,
		RESULT_INVALID_EMAIL = k_EResultInvalidEmail,
		RESULT_DUPLICATE_NAME = k_EResultDuplicateName,
		RESULT_ACCESS_DENIED = k_EResultAccessDenied,
		RESULT_TIMEOUT = k_EResultTimeout,
		RESULT_BANNED = k_EResultBanned,
		RESULT_ACCOUNT_NOT_FOUND = k_EResultAccountNotFound,
		RESULT_INVALID_STEAMID = k_EResultInvalidSteamID,
		RESULT_SERVICE_UNAVAILABLE = k_EResultServiceUnavailable,
		RESULT_NOT_LOGGED_ON = k_EResultNotLoggedOn,
		RESULT_PENDING = k_EResultPending,
		RESULT_ENCRYPTION_FAILURE = k_EResultEncryptionFailure,
		RESULT_INSUFFICIENT_PRIVILEGE = k_EResultInsufficientPrivilege,
		RESULT_LIMIT_EXCEEDED = k_EResultLimitExceeded,
		RESULT_REVOKED = k_EResultRevoked,
		RESULT_EXPIRED = k_EResultExpired,
		RESULT_ALREADY_REDEEMED = k_EResultAlreadyRedeemed,
		RESULT_DUPLICATE_REQUEST = k_EResultDuplicateRequest,
		RESULT_ALREADY_OWNED = k_EResultAlreadyOwned,
		RESULT_IP_NOT_FOUND = k_EResultIPNotFound,
		RESULT_PERSIST_FAILED = k_EResultPersistFailed,
		RESULT_LOCKING_FAILED = k_EResultLockingFailed,
		RESULT_LOG_ON_SESSION_REPLACED = k_EResultLogonSessionReplaced,
		RESULT_CONNECT_FAILED = k_EResultConnectFailed,
		RESULT_HANDSHAKE_FAILED = k_EResultHandshakeFailed,
		RESULT_IO_FAILURE = k_EResultIOFailure,
		RESULT_REMOTE_DISCONNECT = k_EResultRemoteDisconnect,
		RESULT_SHOPPING_CART_NOT_FOUND = k_EResultShoppingCartNotFound,
		RESULT_BLOCKED = k_EResultBlocked,
		RESULT_IGNORED = k_EResultIgnored,
		RESULT_NO_MATCH = k_EResultNoMatch,
		RESULT_ACCOUNT_DISABLED = k_EResultAccountDisabled,
		RESULT_SERVICE_READ_ONLY = k_EResultServiceReadOnly,
		RESULT_ACCOUNT_NOT_FEATURED = k_EResultAccountNotFeatured,
		RESULT_ADMINISTRATO_ROK = k_EResultAdministratorOK,
		RESULT_CONTENT_VERSION = k_EResultContentVersion,
		RESULT_TRY_ANOTHER_CM = k_EResultTryAnotherCM,
		RESULT_PASSWORD_REQUIRED_TO_KICK_SESSION = k_EResultPasswordRequiredToKickSession,
		RESULT_ALREADY_LOGGED_IN_ELSEWHERE = k_EResultAlreadyLoggedInElsewhere,
		RESULT_SUSPENDED = k_EResultSuspended,
		RESULT_CANCELLED = k_EResultCancelled,
		RESULT_DATA_CORRUPTION = k_EResultDataCorruption,
		RESULT_DISK_FULL = k_EResultDiskFull,
		RESULT_REMOTE_CALL_FAILED = k_EResultRemoteCallFailed,
		RESULT_PASSWORD_UNSET = k_EResultPasswordUnset,
		RESULT_EXTERNAL_ACCOUNT_UNLINKED = k_EResultExternalAccountUnlinked,
		RESULT_PSN_TICKET_INVALID = k_EResultPSNTicketInvalid,
		RESULT_EXTERNAL_ACCOUNT_ALREADY_LINKED = k_EResultExternalAccountAlreadyLinked,
		RESULT_REMOTE_FILE_CONFLICT = k_EResultRemoteFileConflict,
		RESULT_ILLEGAL_PASSWORD = k_EResultIllegalPassword,
		RESULT_SAME_AS_PREVIOUS_VALUE = k_EResultSameAsPreviousValue,
		RESULT_ACCOUNT_LOG_ON_DENIED = k_EResultAccountLogonDenied,
		RESULT_CANNOT_USE_OLD_PASSWORD = k_EResultCannotUseOldPassword,
		RESULT_INVALID_LOG_IN_AUTH_CODE = k_EResultInvalidLoginAuthCode,
		RESULT_ACCOUNT_LOG_ON_DENIED_NO_MAIL = k_EResultAccountLogonDeniedNoMail,
		RESULT_HARDWARE_NOT_CAPABLE_OF_IPT = k_EResultHardwareNotCapableOfIPT,
		RESULT_IPT_INIT_ERROR = k_EResultIPTInitError,
		RESULT_PARENTAL_CONTROL_RESTRICTED = k_EResultParentalControlRestricted,
		RESULT_FACEBOOK_QUERY_ERROR = k_EResultFacebookQueryError,
		RESULT_EXPIRED_LOGIN_AUTH_CODE = k_EResultExpiredLoginAuthCode,
		RESULT_IP_LOGIN_RESTRICTION_FAILED = k_EResultIPLoginRestrictionFailed,
		RESULT_ACCOUNT_LOCKED_DOWN = k_EResultAccountLockedDown,
		RESULT_ACCOUNT_LOG_ON_DENIED_VERIFIED_EMAIL_REQUIRED = k_EResultAccountLogonDeniedVerifiedEmailRequired,
		RESULT_NO_MATCHING_URL = k_EResultNoMatchingURL,
		RESULT_BAD_RESPONSE = k_EResultBadResponse,
		RESULT_REQUIRE_PASSWORD_REENTRY = k_EResultRequirePasswordReEntry,
		RESULT_VALUE_OUT_OF_RANGE = k_EResultValueOutOfRange,
		RESULT_UNEXPECTED_ERROR = k_EResultUnexpectedError,
		RESULT_DISABLED = k_EResultDisabled,
		RESULT_INVALID_CEG_SUBMISSION = k_EResultInvalidCEGSubmission,
		RESULT_RESTRICTED_DEVICE = k_EResultRestrictedDevice,
		RESULT_REGION_LOCKED = k_EResultRegionLocked,
		RESULT_RATE_LIMIT_EXCEEDED = k_EResultRateLimitExceeded,
		RESULT_ACCOUNT_LOGIN_DENIED_NEED_TWO_FACTOR = k_EResultAccountLoginDeniedNeedTwoFactor,
		RESULT_ITEM_DELETED = k_EResultItemDeleted,
		RESULT_ACCOUNT_LOGIN_DENIED_THROTTLE = k_EResultAccountLoginDeniedThrottle,
		RESULT_TWO_FACTOR_CODE_MISMATCH = k_EResultTwoFactorCodeMismatch,
		RESULT_TWO_FACTOR_ACTIVATION_CODE_MISMATCH = k_EResultTwoFactorActivationCodeMismatch,
		RESULT_ACCOUNT_ASSOCIATED_TO_MULTIPLE_PARTNERS = k_EResultAccountAssociatedToMultiplePartners,
		RESULT_NOT_MODIFIED = k_EResultNotModified,
		RESULT_NO_MOBILE_DEVICE = k_EResultNoMobileDevice,
		RESULT_TIME_NOT_SYNCED = k_EResultTimeNotSynced,
		RESULT_SMS_CODE_FAILED = k_EResultSmsCodeFailed,
		RESULT_ACCOUNT_LIMIT_EXCEEDED = k_EResultAccountLimitExceeded,
		RESULT_ACCOUNT_ACTIVITY_LIMIT_EXCEEDED = k_EResultAccountActivityLimitExceeded,
		RESULT_PHONE_ACTIVITY_LIMIT_EXCEEDED = k_EResultPhoneActivityLimitExceeded,
		RESULT_REFUND_TO_WALLET = k_EResultRefundToWallet,
		RESULT_EMAIL_SEND_FAILURE = k_EResultEmailSendFailure,
		RESULT_NOT_SETTLED = k_EResultNotSettled,
		RESULT_NEED_CAPTCHA = k_EResultNeedCaptcha,
		RESULT_GSLT_DENIED = k_EResultGSLTDenied,
		RESULT_GS_OWNER_DENIED = k_EResultGSOwnerDenied,
		RESULT_INVALID_ITEM_TYPE = k_EResultInvalidItemType,
		RESULT_IP_BANNED = k_EResultIPBanned,
		RESULT_GSLT_EXPIRED = k_EResultGSLTExpired,
		RESULT_INSUFFICIENT_FUNDS = k_EResultInsufficientFunds,
		RESULT_TOO_MANY_PENDING = k_EResultTooManyPending,
		RESULT_NO_SITE_LICENSES_FOUND = k_EResultNoSiteLicensesFound,
		RESULT_WG_NETWORK_SEND_EXCEEDED = k_EResultWGNetworkSendExceeded,
		RESULT_ACCOUNT_NOT_FRIENDS = k_EResultAccountNotFriends,
		RESULT_LIMITED_USER_ACCOUNT = k_EResultLimitedUserAccount,
		RESULT_CANT_REMOVE_ITEM = k_EResultCantRemoveItem,
		RESULT_ACCOUNT_DELETED = k_EResultAccountDeleted,
		RESULT_EXISTING_USER_CANCELLED_LICENSE = k_EResultExistingUserCancelledLicense,
		RESULT_COMMUNITY_COOLDOWN = k_EResultCommunityCooldown,
		RESULT_NO_LAUNCHER_SPECIFIED = k_EResultNoLauncherSpecified,
		RESULT_MUST_AGREE_TO_SSA = k_EResultMustAgreeToSSA,
		RESULT_LAUNCHER_MIGRATED = k_EResultLauncherMigrated,
		RESULT_STEAM_REALM_MISMATCH = k_EResultSteamRealmMismatch,
		RESULT_INVALID_SIGNATURE = k_EResultInvalidSignature,
		RESULT_PARSE_FAILURE = k_EResultParseFailure,
		RESULT_NO_VERIFIED_PHONE = k_EResultNoVerifiedPhone,
		RESULT_INSUFFICIENT_BATTERY = k_EResultInsufficientBattery,
		RESULT_CHARGER_REQUIRED = k_EResultChargerRequired,
		RESULT_CACHED_CREDENTIAL_INVALID = k_EResultCachedCredentialInvalid,
		RESULT_PHONE_NUMBER_IS_VOIP = K_EResultPhoneNumberIsVOIP,
		RESULT_NOT_SUPPORTED = k_EResultNotSupported,
		RESULT_FAMILY_SIZE_LIMIT_EXCEEDED = k_EResultFamilySizeLimitExceeded
	};
	enum ServerMode {
		SERVER_MODE_INVALID = eServerModeInvalid,
		SERVER_MODE_NO_AUTHENTICATION = eServerModeNoAuthentication,
		SERVER_MODE_AUTHENTICATION = eServerModeAuthentication,
		SERVER_MODE_AUTHENTICATION_AND_SECURE = eServerModeAuthenticationAndSecure
	};
	enum SteamAPIInitResult {
		STEAM_API_INIT_RESULT_OK = k_ESteamAPIInitResult_OK,
		STEAM_API_INIT_RESULT_FAILED_GENERIC = k_ESteamAPIInitResult_FailedGeneric,
		STEAM_API_INIT_RESULT_NO_STEAM_CLIENT = k_ESteamAPIInitResult_NoSteamClient,
		STEAM_API_INIT_RESULT_VERSION_MISMATCH = k_ESteamAPIInitResult_VersionMismatch
	};
	enum Universe {
		// Found in steamuniverse.h
		UNIVERSE_INVALID = k_EUniverseInvalid,
		UNIVERSE_PUBLIC = k_EUniversePublic,
		UNIVERSE_BETA = k_EUniverseBeta,
		UNIVERSE_INTERNAL = k_EUniverseInternal,
		UNIVERSE_DEV = k_EUniverseDev,
		UNIVERSE_MAX = k_EUniverseMax
	};

	// HTTP enums
	enum HTTPMethod {
		HTTP_METHOD_INVALID = k_EHTTPMethodInvalid,
		HTTP_METHOD_GET = k_EHTTPMethodGET,
		HTTP_METHOD_HEAD = k_EHTTPMethodHEAD,
		HTTP_METHOD_POST = k_EHTTPMethodPOST,
		HTTP_METHOD_PUT = k_EHTTPMethodPUT,
		HTTP_METHOD_DELETE = k_EHTTPMethodDELETE,
		HTTP_METHOD_OPTIONS = k_EHTTPMethodOPTIONS,
		HTTP_METHOD_PATCH = k_EHTTPMethodPATCH
	};
	enum HTTPStatusCode {
		HTTP_STATUS_CODE_INVALID = k_EHTTPStatusCodeInvalid,
		HTTP_STATUS_CODE_100_CONTINUE = k_EHTTPStatusCode100Continue,
		HTTP_STATUS_CODE_101_SWITCHING_PROTOCOLS = k_EHTTPStatusCode101SwitchingProtocols,
		HTTP_STATUS_CODE_200_OK = k_EHTTPStatusCode200OK,
		HTTP_STATUS_CODE_201_CREATED = k_EHTTPStatusCode201Created,
		HTTP_STATUS_CODE_202_ACCEPTED = k_EHTTPStatusCode202Accepted,
		HTTP_STATUS_CODE_203_NON_AUTHORITATIVE = k_EHTTPStatusCode203NonAuthoritative,
		HTTP_STATUS_CODE_204_NO_CONTENT = k_EHTTPStatusCode204NoContent,
		HTTP_STATUS_CODE_205_RESET_CONTENT = k_EHTTPStatusCode205ResetContent,
		HTTP_STATUS_CODE_206_PARTIAL_CONTENT = k_EHTTPStatusCode206PartialContent,
		HTTP_STATUS_CODE_300_MULTIPLE_CHOICES = k_EHTTPStatusCode300MultipleChoices,
		HTTP_STATUS_CODE_301_MOVED_PERMANENTLY = k_EHTTPStatusCode301MovedPermanently,
		HTTP_STATUS_CODE_302_FOUND = k_EHTTPStatusCode302Found,
		HTTP_STATUS_CODE_303_SEE_OTHER = k_EHTTPStatusCode303SeeOther,
		HTTP_STATUS_CODE_304_NOT_MODIFIED = k_EHTTPStatusCode304NotModified,
		HTTP_STATUS_CODE_305_USE_PROXY = k_EHTTPStatusCode305UseProxy,
		HTTP_STATUS_CODE_307_TEMPORARY_REDIRECT = k_EHTTPStatusCode307TemporaryRedirect,
		HTTP_STATUS_CODE_308_PERMANENT_REDIRECT = k_EHTTPStatusCode308PermanentRedirect,
		HTTP_STATUS_CODE_400_BAD_REQUEST = k_EHTTPStatusCode400BadRequest,
		HTTP_STATUS_CODE_401_UNAUTHORIZED = k_EHTTPStatusCode401Unauthorized,
		HTTP_STATUS_CODE_402_PAYMENT_REQUIRED = k_EHTTPStatusCode402PaymentRequired,
		HTTP_STATUS_CODE_403_FORBIDDEN = k_EHTTPStatusCode403Forbidden,
		HTTP_STATUS_CODE_404_NOT_FOUND = k_EHTTPStatusCode404NotFound,
		HTTP_STATUS_CODE_405_METHOD_NOT_ALLOWED = k_EHTTPStatusCode405MethodNotAllowed,
		HTTP_STATUS_CODE_406_NOT_ACCEPTABLE = k_EHTTPStatusCode406NotAcceptable,
		HTTP_STATUS_CODE_407_PROXY_AUTH_REQUIRED = k_EHTTPStatusCode407ProxyAuthRequired,
		HTTP_STATUS_CODE_408_REQUEST_TIMEOUT = k_EHTTPStatusCode408RequestTimeout,
		HTTP_STATUS_CODE_409_CONFLICT = k_EHTTPStatusCode409Conflict,
		HTTP_STATUS_CODE_410_GONE = k_EHTTPStatusCode410Gone,
		HTTP_STATUS_CODE_411_LENGTH_REQUIRED = k_EHTTPStatusCode411LengthRequired,
		HTTP_STATUS_CODE_412_PRECONDITION_FAILED = k_EHTTPStatusCode412PreconditionFailed,
		HTTP_STATUS_CODE_413_REQUEST_ENTITY_TOO_LARGE = k_EHTTPStatusCode413RequestEntityTooLarge,
		HTTP_STATUS_CODE_414_REQUEST_URI_TOO_LONG = k_EHTTPStatusCode414RequestURITooLong,
		HTTP_STATUS_CODE_415_UNSUPPORTED_MEDIA_TYPE = k_EHTTPStatusCode415UnsupportedMediaType,
		HTTP_STATUS_CODE_416_REQUESTED_RANGE_NOT_SATISFIABLE = k_EHTTPStatusCode416RequestedRangeNotSatisfiable,
		HTTP_STATUS_CODE_417_EXPECTATION_FAILED = k_EHTTPStatusCode417ExpectationFailed,
		HTTP_STATUS_CODE_4XX_UNKNOWN = k_EHTTPStatusCode4xxUnknown,
		HTTP_STATUS_CODE_429_TOO_MANY_REQUESTS = k_EHTTPStatusCode429TooManyRequests,
		HTTP_STATUS_CODE_444_CONNECTION_CLOSED = k_EHTTPStatusCode444ConnectionClosed,
		HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR = k_EHTTPStatusCode500InternalServerError,
		HTTP_STATUS_CODE_501_NOT_IMPLEMENTED = k_EHTTPStatusCode501NotImplemented,
		HTTP_STATUS_CODE_502_BAD_GATEWAY = k_EHTTPStatusCode502BadGateway,
		HTTP_STATUS_CODE_503_SERVICE_UNAVAILABLE = k_EHTTPStatusCode503ServiceUnavailable,
		HTTP_STATUS_CODE_504_GATEWAY_TIMEOUT = k_EHTTPStatusCode504GatewayTimeout,
		HTTP_STATUS_CODE_505_HTTP_VERSION_NOT_SUPPORTED = k_EHTTPStatusCode505HTTPVersionNotSupported,
		HTTP_STATUS_CODE_5XX_UNKNOWN = k_EHTTPStatusCode5xxUnknown
	};

	// Inventory enums
	enum ItemFlags {
		STEAM_ITEM_NO_TRADE = k_ESteamItemNoTrade,
		STEAM_ITEM_REMOVED = k_ESteamItemRemoved,
		STEAM_ITEM_CONSUMED = k_ESteamItemConsumed
	};

	// Networking enums
	enum P2PSend {
		P2P_SEND_UNRELIABLE = k_EP2PSendUnreliable,
		P2P_SEND_UNRELIABLE_NO_DELAY = k_EP2PSendUnreliableNoDelay,
		P2P_SEND_RELIABLE = k_EP2PSendReliable,
		P2P_SEND_RELIABLE_WITH_BUFFERING = k_EP2PSendReliableWithBuffering
	};
	enum P2PSessionError {
		P2P_SESSION_ERROR_NONE = k_EP2PSessionErrorNone,
		P2P_SESSION_ERROR_NOT_RUNNING_APP = k_EP2PSessionErrorNotRunningApp_DELETED,
		P2P_SESSION_ERROR_NO_RIGHTS_TO_APP = k_EP2PSessionErrorNoRightsToApp,
		P2P_SESSION_ERROR_DESTINATION_NOT_LOGGED_ON = k_EP2PSessionErrorDestinationNotLoggedIn_DELETED,
		P2P_SESSION_ERROR_TIMEOUT = k_EP2PSessionErrorTimeout,
		P2P_SESSION_ERROR_MAX = k_EP2PSessionErrorMax
	};
	enum SocketConnectionType {
		NET_SOCKET_CONNECTION_TYPE_NOT_CONNECTED = k_ESNetSocketConnectionTypeNotConnected,
		NET_SOCKET_CONNECTION_TYPE_UDP = k_ESNetSocketConnectionTypeUDP,
		NET_SOCKET_CONNECTION_TYPE_UDP_RELAY = k_ESNetSocketConnectionTypeUDPRelay
	};
	enum SocketState {
		NET_SOCKET_STATE_INVALID = k_ESNetSocketStateInvalid,
		NET_SOCKET_STATE_CONNECTED = k_ESNetSocketStateConnected,
		NET_SOCKET_STATE_INITIATED = k_ESNetSocketStateInitiated,
		NET_SOCKET_STATE_LOCAL_CANDIDATE_FOUND = k_ESNetSocketStateLocalCandidatesFound,
		NET_SOCKET_STATE_RECEIVED_REMOTE_CANDIDATES = k_ESNetSocketStateReceivedRemoteCandidates,
		NET_SOCKET_STATE_CHALLENGE_HANDSHAKE = k_ESNetSocketStateChallengeHandshake,
		NET_SOCKET_STATE_DISCONNECTING = k_ESNetSocketStateDisconnecting,
		NET_SOCKET_STATE_LOCAL_DISCONNECT = k_ESNetSocketStateLocalDisconnect,
		NET_SOCKET_STATE_TIMEOUT_DURING_CONNECT = k_ESNetSocketStateTimeoutDuringConnect,
		NET_SOCKET_STATE_REMOTE_END_DISCONNECTED = k_ESNetSocketStateRemoteEndDisconnected,
		NET_SOCKET_STATE_BROKEN = k_ESNetSocketStateConnectionBroken
	};

	// Networking Sockets enums
	enum NetworkingConfigValue {
		NETWORKING_CONFIG_INVALID = k_ESteamNetworkingConfig_Invalid,
		NETWORKING_CONFIG_FAKE_PACKET_LOSS_SEND = k_ESteamNetworkingConfig_FakePacketLoss_Send,
		NETWORKING_CONFIG_FAKE_PACKET_LOSS_RECV = k_ESteamNetworkingConfig_FakePacketLoss_Recv,
		NETWORKING_CONFIG_FAKE_PACKET_LAG_SEND = k_ESteamNetworkingConfig_FakePacketLag_Send,
		NETWORKING_CONFIG_FAKE_PACKET_LAG_RECV = k_ESteamNetworkingConfig_FakePacketLag_Recv,
		NETWORKING_CONFIG_FAKE_PACKET_REORDER_SEND = k_ESteamNetworkingConfig_FakePacketReorder_Send,
		NETWORKING_CONFIG_FAKE_PACKET_REORDER_RECV = k_ESteamNetworkingConfig_FakePacketReorder_Recv,
		NETWORKING_CONFIG_FAKE_PACKET_REORDER_TIME = k_ESteamNetworkingConfig_FakePacketReorder_Time,
		NETWORKING_CONFIG_FAKE_PACKET_DUP_SEND = k_ESteamNetworkingConfig_FakePacketDup_Send,
		NETWORKING_CONFIG_FAKE_PACKET_DUP_REVC = k_ESteamNetworkingConfig_FakePacketDup_Recv,
		NETWORKING_CONFIG_FAKE_PACKET_DUP_TIME_MAX = k_ESteamNetworkingConfig_FakePacketDup_TimeMax,
		NETWORKING_CONFIG_PACKET_TRACE_MAX_BYTES = k_ESteamNetworkingConfig_PacketTraceMaxBytes,
		NETWORKING_CONFIG_FAKE_RATE_LIMIT_SEND_RATE = k_ESteamNetworkingConfig_FakeRateLimit_Send_Rate,
		NETWORKING_CONFIG_FAKE_RATE_LIMIT_SEND_BURST = k_ESteamNetworkingConfig_FakeRateLimit_Send_Burst,
		NETWORKING_CONFIG_FAKE_RATE_LIMIT_RECV_RATE = k_ESteamNetworkingConfig_FakeRateLimit_Recv_Rate,
		NETWORKING_CONFIG_FAKE_RATE_LIMIT_RECV_BURST = k_ESteamNetworkingConfig_FakeRateLimit_Recv_Burst,
		NETWORKING_CONFIG_OUT_OF_ORDER_CORRECTION_WINDOW_MICROSECONDS = k_ESteamNetworkingConfig_OutOfOrderCorrectionWindowMicroseconds,
		NETWORKING_CONFIG_CONNECTION_USER_DATA = k_ESteamNetworkingConfig_ConnectionUserData,
		NETWORKING_CONFIG_TIMEOUT_INITIAL = k_ESteamNetworkingConfig_TimeoutInitial,
		NETWORKING_CONFIG_TIMEOUT_CONNECTED = k_ESteamNetworkingConfig_TimeoutConnected,
		NETWORKING_CONFIG_SEND_BUFFER_SIZE = k_ESteamNetworkingConfig_SendBufferSize,
		NETWORKING_CONFIG_RECV_BUFFER_SIZE = k_ESteamNetworkingConfig_RecvBufferSize,
		NETWORKING_CONFIG_RECV_BUFFER_MESSAGES = k_ESteamNetworkingConfig_RecvBufferMessages,
		NETWORKING_CONFIG_RECV_MAX_MESSAGE_SIZE = k_ESteamNetworkingConfig_RecvMaxMessageSize,
		NETWORKING_CONFIG_RECV_MAX_SEGMENTS_PER_PACKET = k_ESteamNetworkingConfig_RecvMaxSegmentsPerPacket,
		NETWORKING_CONFIG_SEND_RATE_MIN = k_ESteamNetworkingConfig_SendRateMin,
		NETWORKING_CONFIG_SEND_RATE_MAX = k_ESteamNetworkingConfig_SendRateMax,
		NETWORKING_CONFIG_NAGLE_TIME = k_ESteamNetworkingConfig_NagleTime,
		NETWORKING_CONFIG_IP_ALLOW_WITHOUT_AUTH = k_ESteamNetworkingConfig_IP_AllowWithoutAuth,
		NETWORKING_CONFIG_MTU_PACKET_SIZE = k_ESteamNetworkingConfig_MTU_PacketSize,
		NETWORKING_CONFIG_MTU_DATA_SIZE = k_ESteamNetworkingConfig_MTU_DataSize,
		NETWORKING_CONFIG_UNENCRYPTED = k_ESteamNetworkingConfig_Unencrypted,
		NETWORKING_CONFIG_SYMMETRIC_CONNECT = k_ESteamNetworkingConfig_SymmetricConnect,
		NETWORKING_CONFIG_LOCAL_VIRTUAL_PORT = k_ESteamNetworkingConfig_LocalVirtualPort,
		NETWORKING_CONFIG_DUAL_WIFI_ENABLE = k_ESteamNetworkingConfig_DualWifi_Enable,
		NETWORKING_CONFIG_ENABLE_DIAGNOSTICS_UI = k_ESteamNetworkingConfig_EnableDiagnosticsUI,
		NETWORKING_CONFIG_SDR_CLIENT_CONSEC_PING_TIMEOUT_FAIL_INITIAL = k_ESteamNetworkingConfig_SDRClient_ConsecutitivePingTimeoutsFailInitial,
		NETWORKING_CONFIG_SDR_CLIENT_CONSEC_PING_TIMEOUT_FAIL = k_ESteamNetworkingConfig_SDRClient_ConsecutitivePingTimeoutsFail,
		NETWORKING_CONFIG_SDR_CLIENT_MIN_PINGS_BEFORE_PING_ACCURATE = k_ESteamNetworkingConfig_SDRClient_MinPingsBeforePingAccurate,
		NETWORKING_CONFIG_SDR_CLIENT_SINGLE_SOCKET = k_ESteamNetworkingConfig_SDRClient_SingleSocket,
		NETWORKING_CONFIG_SDR_CLIENT_FORCE_RELAY_CLUSTER = k_ESteamNetworkingConfig_SDRClient_ForceRelayCluster,
		NETWORKING_CONFIG_SDR_CLIENT_DEV_TICKET = k_ESteamNetworkingConfig_SDRClient_DevTicket,
		NETWORKING_CONFIG_SDR_CLIENT_FORCE_PROXY_ADDR = k_ESteamNetworkingConfig_SDRClient_ForceProxyAddr,
		NETWORKING_CONFIG_SDR_CLIENT_FAKE_CLUSTER_PING = k_ESteamNetworkingConfig_SDRClient_FakeClusterPing,
		NETWORKING_CONFIG_SDR_CLIENT_LIMIT_PING_PROBES_TO_NEAREST_N = k_ESteamNetworkingConfig_SDRClient_LimitPingProbesToNearestN,
		NETWORKING_CONFIG_LOG_LEVEL_ACK_RTT = k_ESteamNetworkingConfig_LogLevel_AckRTT,
		NETWORKING_CONFIG_LOG_LEVEL_PACKET_DECODE = k_ESteamNetworkingConfig_LogLevel_PacketDecode,
		NETWORKING_CONFIG_LOG_LEVEL_MESSAGE = k_ESteamNetworkingConfig_LogLevel_Message,
		NETWORKING_CONFIG_LOG_LEVEL_PACKET_GAPS = k_ESteamNetworkingConfig_LogLevel_PacketGaps,
		NETWORKING_CONFIG_LOG_LEVEL_P2P_RENDEZVOUS = k_ESteamNetworkingConfig_LogLevel_P2PRendezvous,
		NETWORKING_CONFIG_LOG_LEVEL_SRD_RELAY_PINGS = k_ESteamNetworkingConfig_LogLevel_SDRRelayPings,
		NETWORKING_CONFIG_CALLBACK_CONNECTION_STATUS_CHANGED = k_ESteamNetworkingConfig_Callback_ConnectionStatusChanged,
		NETWORKING_CONFIG_CALLBACK_AUTH_STATUS_CHANGED = k_ESteamNetworkingConfig_Callback_AuthStatusChanged,
		NETWORKING_CONFIG_CALLBACK_RELAY_NETWORK_STATUS_CHANGED = k_ESteamNetworkingConfig_Callback_RelayNetworkStatusChanged,
		NETWORKING_CONFIG_CALLBACK_MESSAGE_SESSION_REQUEST = k_ESteamNetworkingConfig_Callback_MessagesSessionRequest,
		NETWORKING_CONFIG_CALLBACK_MESSAGES_SESSION_FAILED = k_ESteamNetworkingConfig_Callback_MessagesSessionFailed,
		NETWORKING_CONFIG_CALLBACK_CREATE_CONNECTION_SIGNALING = k_ESteamNetworkingConfig_Callback_CreateConnectionSignaling,
		NETWORKING_CONFIG_CALLBACK_FAKE_IP_RESULT = k_ESteamNetworkingConfig_Callback_FakeIPResult,
		NETWORKING_CONFIG_P2P_STUN_SERVER_LIST = k_ESteamNetworkingConfig_P2P_STUN_ServerList,
		NETWORKING_CONFIG_P2P_TRANSPORT_ICE_ENABLE = k_ESteamNetworkingConfig_P2P_Transport_ICE_Enable,
		NETWORKING_CONFIG_P2P_TRANSPORT_ICE_PENALTY = k_ESteamNetworkingConfig_P2P_Transport_ICE_Penalty,
		NETWORKING_CONFIG_P2P_TRANSPORT_SDR_PENALTY = k_ESteamNetworkingConfig_P2P_Transport_SDR_Penalty,
		NETWORKING_CONFIG_P2P_TURN_SERVER_LIST = k_ESteamNetworkingConfig_P2P_TURN_ServerList,
		NETWORKING_CONFIG_P2P_TURN_uSER_LIST = k_ESteamNetworkingConfig_P2P_TURN_UserList,
		NETWORKING_CONFIG_P2P_TURN_PASS_LIST = k_ESteamNetworkingConfig_P2P_TURN_PassList,
		//			NETWORKING_CONFIG_P2P_TRANSPORT_LAN_BEACON_PENALTY = k_ESteamNetworkingConfig_P2P_Transport_LANBeacon_Penalty,
		NETWORKING_CONFIG_P2P_TRANSPORT_ICE_IMPLEMENTATION = k_ESteamNetworkingConfig_P2P_Transport_ICE_Implementation,
		NETWORKING_CONFIG_ECN = k_ESteamNetworkingConfig_ECN,
		NETWORKING_CONFIG_VALUE_FORCE32BIT = k_ESteamNetworkingConfigValue__Force32Bit
	};
	enum NetworkingConnectionEnd {
		CONNECTION_END_INVALID = k_ESteamNetConnectionEnd_Invalid,
		CONNECTION_END_APP_MIN = k_ESteamNetConnectionEnd_App_Min,
		CONNECTION_END_APP_GENERIC = k_ESteamNetConnectionEnd_App_Generic,
		CONNECTION_END_APP_MAX = k_ESteamNetConnectionEnd_App_Max,
		CONNECTION_END_APP_EXCEPTION_MIN = k_ESteamNetConnectionEnd_AppException_Min,
		CONNECTION_END_APP_EXCEPTION_GENERIC = k_ESteamNetConnectionEnd_AppException_Generic,
		CONNECTION_END_APP_EXCEPTION_MAX = k_ESteamNetConnectionEnd_AppException_Max,
		CONNECTION_END_LOCAL_MIN = k_ESteamNetConnectionEnd_Local_Min,
		CONNECTION_END_LOCAL_OFFLINE_MODE = k_ESteamNetConnectionEnd_Local_OfflineMode,
		CONNECTION_END_LOCAL_MANY_RELAY_CONNECTIVITY = k_ESteamNetConnectionEnd_Local_ManyRelayConnectivity,
		CONNECTION_END_LOCAL_HOSTED_SERVER_PRIMARY_RELAY = k_ESteamNetConnectionEnd_Local_HostedServerPrimaryRelay,
		CONNECTION_END_LOCAL_NETWORK_CONFIG = k_ESteamNetConnectionEnd_Local_NetworkConfig,
		CONNECTION_END_LOCAL_RIGHTS = k_ESteamNetConnectionEnd_Local_Rights,
		CONNECTION_END_NO_PUBLIC_ADDRESS = k_ESteamNetConnectionEnd_Local_P2P_ICE_NoPublicAddresses,
		CONNECTION_END_LOCAL_MAX = k_ESteamNetConnectionEnd_Local_Max,
		CONNECTION_END_REMOVE_MIN = k_ESteamNetConnectionEnd_Remote_Min,
		CONNECTION_END_REMOTE_TIMEOUT = k_ESteamNetConnectionEnd_Remote_Timeout,
		CONNECTION_END_REMOTE_BAD_CRYPT = k_ESteamNetConnectionEnd_Remote_BadCrypt,
		CONNECTION_END_REMOTE_BAD_CERT = k_ESteamNetConnectionEnd_Remote_BadCert,
		CONNECTION_END_BAD_PROTOCOL_VERSION = k_ESteamNetConnectionEnd_Remote_BadProtocolVersion,
		CONNECTION_END_REMOTE_P2P_ICE_NO_PUBLIC_ADDRESSES = k_ESteamNetConnectionEnd_Remote_P2P_ICE_NoPublicAddresses,
		CONNECTION_END_REMOTE_MAX = k_ESteamNetConnectionEnd_Remote_Max,
		CONNECTION_END_MISC_MIN = k_ESteamNetConnectionEnd_Misc_Min,
		CONNECTION_END_MISC_GENERIC = k_ESteamNetConnectionEnd_Misc_Generic,
		CONNECTION_END_MISC_INTERNAL_ERROR = k_ESteamNetConnectionEnd_Misc_InternalError,
		CONNECTION_END_MISC_TIMEOUT = k_ESteamNetConnectionEnd_Misc_Timeout,
		CONNECTION_END_MISC_STEAM_CONNECTIVITY = k_ESteamNetConnectionEnd_Misc_SteamConnectivity,
		CONNECTION_END_MISC_NO_RELAY_SESSIONS_TO_CLIENT = k_ESteamNetConnectionEnd_Misc_NoRelaySessionsToClient,
		CONNECTION_END_MISC_P2P_RENDEZVOUS = k_ESteamNetConnectionEnd_Misc_P2P_Rendezvous,
		CONNECTION_END_MISC_P2P_NAT_FIREWALL = k_ESteamNetConnectionEnd_Misc_P2P_NAT_Firewall,
		CONNECTION_END_MISC_PEER_SENT_NO_CONNECTION = k_ESteamNetConnectionEnd_Misc_PeerSentNoConnection,
		CONNECTION_END_MISC_MAX = k_ESteamNetConnectionEnd_Misc_Max,
		CONNECTION_END_FORCE32BIT = k_ESteamNetConnectionEnd__Force32Bit
	};
	enum NetworkingConnectionState {
		CONNECTION_STATE_NONE = k_ESteamNetworkingConnectionState_None,
		CONNECTION_STATE_CONNECTING = k_ESteamNetworkingConnectionState_Connecting,
		CONNECTION_STATE_FINDING_ROUTE = k_ESteamNetworkingConnectionState_FindingRoute,
		CONNECTION_STATE_CONNECTED = k_ESteamNetworkingConnectionState_Connected,
		CONNECTION_STATE_CLOSED_BY_PEER = k_ESteamNetworkingConnectionState_ClosedByPeer,
		CONNECTION_STATE_PROBLEM_DETECTED_LOCALLY = k_ESteamNetworkingConnectionState_ProblemDetectedLocally,
		CONNECTION_STATE_FIN_WAIT = k_ESteamNetworkingConnectionState_FinWait,
		CONNECTION_STATE_LINGER = k_ESteamNetworkingConnectionState_Linger,
		CONNECTION_STATE_DEAD = k_ESteamNetworkingConnectionState_Dead,
		CONNECTION_STATE_FORCE_32BIT = k_ESteamNetworkingConnectionState__Force32Bit
	};
	enum NetworkingFakeIPType {
		FAKE_IP_TYPE_INVALID = k_ESteamNetworkingFakeIPType_Invalid,
		FAKE_IP_TYPE_NOT_FAKE = k_ESteamNetworkingFakeIPType_NotFake,
		FAKE_IP_TYPE_GLOBAL_IPV4 = k_ESteamNetworkingFakeIPType_GlobalIPv4,
		FAKE_IP_TYPE_LOCAL_IPV4 = k_ESteamNetworkingFakeIPType_LocalIPv4,
		FAKE_IP_TYPE_FORCE32BIT = k_ESteamNetworkingFakeIPType__Force32Bit
	};
	enum NetworkingGetConfigValueResult {
		NETWORKING_GET_CONFIG_VALUE_BAD_VALUE = k_ESteamNetworkingGetConfigValue_BadValue,
		NETWORKING_GET_CONFIG_VALUE_BAD_SCOPE_OBJ = k_ESteamNetworkingGetConfigValue_BadScopeObj,
		NETWORKING_GET_CONFIG_VALUE_BUFFER_TOO_SMALL = k_ESteamNetworkingGetConfigValue_BufferTooSmall,
		NETWORKING_GET_CONFIG_VALUE_OK = k_ESteamNetworkingGetConfigValue_OK,
		NETWORKING_GET_CONFIG_VALUE_OK_INHERITED = k_ESteamNetworkingGetConfigValue_OKInherited,
		NETWORKING_GET_CONFIG_VALUE_FORCE_32BIT = k_ESteamNetworkingGetConfigValueResult__Force32Bit
	};
	enum NetworkingIdentityType {
		IDENTITY_TYPE_INVALID = k_ESteamNetworkingIdentityType_Invalid,
		IDENTITY_TYPE_STEAMID = k_ESteamNetworkingIdentityType_SteamID,
		IDENTITY_TYPE_IP_ADDRESS = k_ESteamNetworkingIdentityType_IPAddress,
		IDENTITY_TYPE_GENERIC_STRING = k_ESteamNetworkingIdentityType_GenericString,
		IDENTITY_TYPE_GENERIC_BYTES = k_ESteamNetworkingIdentityType_GenericBytes,
		IDENTITY_TYPE_UNKNOWN_TYPE = k_ESteamNetworkingIdentityType_UnknownType,
		IDENTITY_TYPE_XBOX_PAIRWISE = k_ESteamNetworkingIdentityType_XboxPairwiseID,
		IDENTITY_TYPE_SONY_PSN = k_ESteamNetworkingIdentityType_SonyPSN,
		IDENTITY_TYPE_GOOGLE_STADIA = k_ESteamNetworkingIdentityType_GoogleStadia,
		//			IDENTITY_TYPE_NINTENDO = k_ESteamNetworkingIdentityType_NintendoNetworkServiceAccount,
		//			IDENTITY_TYPE_EPIC_GS = k_ESteamNetworkingIdentityType_EpicGameStore,
		//			IDENTITY_TYPE_WEGAME = k_ESteamNetworkingIdentityType_WeGame,
		IDENTITY_TYPE_FORCE_32BIT = k_ESteamNetworkingIdentityType__Force32bit
	};
	enum NetworkingSocketsDebugOutputType {
		NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_NONE = k_ESteamNetworkingSocketsDebugOutputType_None,
		NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_BUG = k_ESteamNetworkingSocketsDebugOutputType_Bug,
		NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_ERROR = k_ESteamNetworkingSocketsDebugOutputType_Error,
		NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_IMPORTANT = k_ESteamNetworkingSocketsDebugOutputType_Important,
		NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_WARNING = k_ESteamNetworkingSocketsDebugOutputType_Warning,
		NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_MSG = k_ESteamNetworkingSocketsDebugOutputType_Msg,
		NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_VERBOSE = k_ESteamNetworkingSocketsDebugOutputType_Verbose,
		NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_DEBUG = k_ESteamNetworkingSocketsDebugOutputType_Debug,
		NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_EVERYTHING = k_ESteamNetworkingSocketsDebugOutputType_Everything,
		NETWORKING_SOCKET_DEBUG_OUTPUT_TYPE_FORCE_32BIT = k_ESteamNetworkingSocketsDebugOutputType__Force32Bit
	};

	// Networking Utils enums {
	enum NetworkingAvailability {
		NETWORKING_AVAILABILITY_CANNOT_TRY = k_ESteamNetworkingAvailability_CannotTry,
		NETWORKING_AVAILABILITY_FAILED = k_ESteamNetworkingAvailability_Failed,
		NETWORKING_AVAILABILITY_PREVIOUSLY = k_ESteamNetworkingAvailability_Previously,
		NETWORKING_AVAILABILITY_RETRYING = k_ESteamNetworkingAvailability_Retrying,
		NETWORKING_AVAILABILITY_NEVER_TRIED = k_ESteamNetworkingAvailability_NeverTried,
		NETWORKING_AVAILABILITY_WAITING = k_ESteamNetworkingAvailability_Waiting,
		NETWORKING_AVAILABILITY_ATTEMPTING = k_ESteamNetworkingAvailability_Attempting,
		NETWORKING_AVAILABILITY_CURRENT = k_ESteamNetworkingAvailability_Current,
		NETWORKING_AVAILABILITY_UNKNOWN = k_ESteamNetworkingAvailability_Unknown,
		NETWORKING_AVAILABILITY_FORCE_32BIT = k_ESteamNetworkingAvailability__Force32bit
	};
	enum NetworkingConfigDataType {
		NETWORKING_CONFIG_TYPE_INT32 = k_ESteamNetworkingConfig_Int32,
		NETWORKING_CONFIG_TYPE_INT64 = k_ESteamNetworkingConfig_Int64,
		NETWORKING_CONFIG_TYPE_FLOAT = k_ESteamNetworkingConfig_Float,
		NETWORKING_CONFIG_TYPE_STRING = k_ESteamNetworkingConfig_String,
		NETWORKING_CONFIG_TYPE_FUNCTION_PTR = k_ESteamNetworkingConfig_Ptr,
		NETWORKING_CONFIG_TYPE_FORCE_32BIT = k_ESteamNetworkingConfigDataType__Force32Bit
	};
	enum NetworkingConfigScope {
		NETWORKING_CONFIG_SCOPE_GLOBAL = k_ESteamNetworkingConfig_Global,
		NETWORKING_CONFIG_SCOPE_SOCKETS_INTERFACE = k_ESteamNetworkingConfig_SocketsInterface,
		NETWORKING_CONFIG_SCOPE_LISTEN_SOCKET = k_ESteamNetworkingConfig_ListenSocket,
		NETWORKING_CONFIG_SCOPE_CONNECTION = k_ESteamNetworkingConfig_Connection,
		NETWORKING_CONFIG_SCOPE_FORCE_32BIT = k_ESteamNetworkingConfigScope__Force32Bit
	};

	// Remote Storage enums
	enum FilePathType {
		FILE_PATH_TYPE_INVALID = k_ERemoteStorageFilePathType_Invalid,
		FILE_PATH_TYPE_ABSOLUTE = k_ERemoteStorageFilePathType_Absolute,
		FILE_PATH_TYPE_API_FILENAME = k_ERemoteStorageFilePathType_APIFilename
	};
	enum LocalFileChange {
		LOCAL_FILE_CHANGE_INVALID = k_ERemoteStorageLocalFileChange_Invalid,
		LOCAL_FILE_CHANGE_FILE_UPDATED = k_ERemoteStorageLocalFileChange_FileUpdated,
		LOCAL_FILE_CHANGE_FILE_DELETED = k_ERemoteStorageLocalFileChange_FileDeleted
	};
	enum RemoteStoragePlatform {
		REMOTE_STORAGE_PLATFORM_NONE = k_ERemoteStoragePlatformNone,
		REMOTE_STORAGE_PLATFORM_WINDOWS = k_ERemoteStoragePlatformWindows,
		REMOTE_STORAGE_PLATFORM_OSX = k_ERemoteStoragePlatformOSX,
		REMOTE_STORAGE_PLATFORM_PS3 = k_ERemoteStoragePlatformPS3,
		REMOTE_STORAGE_PLATFORM_LINUX = k_ERemoteStoragePlatformLinux,
		REMOTE_STORAGE_PLATFORM_SWITCH = k_ERemoteStoragePlatformSwitch,
		REMOTE_STORAGE_PLATFORM_ANDROID = k_ERemoteStoragePlatformAndroid,
		REMOTE_STORAGE_PLATFORM_IOS = k_ERemoteStoragePlatformIOS,
		REMOTE_STORAGE_PLATFORM_ALL = k_ERemoteStoragePlatformAll
	};
	enum RemoteStoragePublishedFileVisibility {
		REMOTE_STORAGE_PUBLISHED_VISIBILITY_PUBLIC = k_ERemoteStoragePublishedFileVisibilityPublic,
		REMOTE_STORAGE_PUBLISHED_VISIBILITY_FRIENDS_ONLY = k_ERemoteStoragePublishedFileVisibilityFriendsOnly,
		REMOTE_STORAGE_PUBLISHED_VISIBILITY_PRIVATE = k_ERemoteStoragePublishedFileVisibilityPrivate,
		REMOTE_STORAGE_PUBLISHED_VISIBILITY_UNLISTED = k_ERemoteStoragePublishedFileVisibilityUnlisted
	};
	enum UGCReadAction {
		UGC_READ_CONTINUE_READING_UNTIL_FINISHED = k_EUGCRead_ContinueReadingUntilFinished,
		UGC_READ_CONTINUE_READING = k_EUGCRead_ContinueReading,
		UGC_READ_CLOSE = k_EUGCRead_Close
	};
	enum WorkshopEnumerationType {
		WORKSHOP_ENUMERATION_TYPE_RANKED_BY_VOTE = k_EWorkshopEnumerationTypeRankedByVote,
		WORKSHOP_ENUMERATION_TYPE_RECENT = k_EWorkshopEnumerationTypeRecent,
		WORKSHOP_ENUMERATION_TYPE_TRENDING = k_EWorkshopEnumerationTypeTrending,
		WORKSHOP_ENUMERATION_TYPE_FAVORITES_OF_FRIENDS = k_EWorkshopEnumerationTypeFavoritesOfFriends,
		WORKSHOP_ENUMERATION_TYPE_VOTED_BY_FRIENDS = k_EWorkshopEnumerationTypeVotedByFriends,
		WORKSHOP_ENUMERATION_TYPE_CONTENT_BY_FRIENDS = k_EWorkshopEnumerationTypeContentByFriends,
		WORKSHOP_ENUMERATION_TYPE_RECENT_FROM_FOLLOWED_USERS = k_EWorkshopEnumerationTypeRecentFromFollowedUsers
	};
	enum WorkshopFileAction {
		WORKSHOP_FILE_ACTION_PLAYED = k_EWorkshopFileActionPlayed,
		WORKSHOP_FILE_ACTION_COMPLETED = k_EWorkshopFileActionCompleted
	};
	enum WorkshopFileType {
		WORKSHOP_FILE_TYPE_FIRST = k_EWorkshopFileTypeFirst,
		WORKSHOP_FILE_TYPE_COMMUNITY = k_EWorkshopFileTypeCommunity,
		WORKSHOP_FILE_TYPE_MICROTRANSACTION = k_EWorkshopFileTypeMicrotransaction,
		WORKSHOP_FILE_TYPE_COLLECTION = k_EWorkshopFileTypeCollection,
		WORKSHOP_FILE_TYPE_ART = k_EWorkshopFileTypeArt,
		WORKSHOP_FILE_TYPE_VIDEO = k_EWorkshopFileTypeVideo,
		WORKSHOP_FILE_TYPE_SCREENSHOT = k_EWorkshopFileTypeScreenshot,
		WORKSHOP_FILE_TYPE_GAME = k_EWorkshopFileTypeGame,
		WORKSHOP_FILE_TYPE_SOFTWARE = k_EWorkshopFileTypeSoftware,
		WORKSHOP_FILE_TYPE_CONCEPT = k_EWorkshopFileTypeConcept,
		WORKSHOP_FILE_TYPE_WEB_GUIDE = k_EWorkshopFileTypeWebGuide,
		WORKSHOP_FILE_TYPE_INTEGRATED_GUIDE = k_EWorkshopFileTypeIntegratedGuide,
		WORKSHOP_FILE_TYPE_MERCH = k_EWorkshopFileTypeMerch,
		WORKSHOP_FILE_TYPE_CONTROLLER_BINDING = k_EWorkshopFileTypeControllerBinding,
		WORKSHOP_FILE_TYPE_STEAMWORKS_ACCESS_INVITE = k_EWorkshopFileTypeSteamworksAccessInvite,
		WORKSHOP_FILE_TYPE_STEAM_VIDEO = k_EWorkshopFileTypeSteamVideo,
		WORKSHOP_FILE_TYPE_GAME_MANAGED_ITEM = k_EWorkshopFileTypeGameManagedItem,
		WORKSHOP_FILE_TYPE_CLIP = k_EWorkshopFileTypeClip,
		WORKSHOP_FILE_TYPE_MAX = k_EWorkshopFileTypeMax
	};
	enum WorkshopVideoProvider {
		WORKSHOP_VIDEO_PROVIDER_NONE = k_EWorkshopVideoProviderNone,
		WORKSHOP_VIDEO_PROVIDER_YOUTUBE = k_EWorkshopVideoProviderYoutube
	};
	enum WorkshopVote {
		WORKSHOP_VOTE_UNVOTED = k_EWorkshopVoteUnvoted,
		WORKSHOP_VOTE_FOR = k_EWorkshopVoteFor,
		WORKSHOP_VOTE_AGAINST = k_EWorkshopVoteAgainst,
		WORKSHOP_VOTE_LATER = k_EWorkshopVoteLater
	};

	// UGC enums
	enum ItemPreviewType {
		ITEM_PREVIEW_TYPE_IMAGE = k_EItemPreviewType_Image,
		ITEM_PREVIEW_TYPE_YOUTUBE_VIDEO = k_EItemPreviewType_YouTubeVideo,
		ITEM_PREVIEW_TYPE_SKETCHFAB = k_EItemPreviewType_Sketchfab,
		ITEM_PREVIEW_TYPE_ENVIRONMENTMAP_HORIZONTAL_CROSS = k_EItemPreviewType_EnvironmentMap_HorizontalCross,
		ITEM_PREVIEW_TYPE_ENVIRONMENTMAP_LAT_LONG = k_EItemPreviewType_EnvironmentMap_LatLong,
		ITEM_PREVIEW_TYPE_CLIP = k_EItemPreviewType_Clip,
		ITEM_PREVIEW_TYPE_RESERVED_MAX = k_EItemPreviewType_ReservedMax
	};
	enum ItemState {
		ITEM_STATE_NONE = k_EItemStateNone,
		ITEM_STATE_SUBSCRIBED = k_EItemStateSubscribed,
		ITEM_STATE_LEGACY_ITEM = k_EItemStateLegacyItem,
		ITEM_STATE_INSTALLED = k_EItemStateInstalled,
		ITEM_STATE_NEEDS_UPDATE = k_EItemStateNeedsUpdate,
		ITEM_STATE_DOWNLOADING = k_EItemStateDownloading,
		ITEM_STATE_DOWNLOAD_PENDING = k_EItemStateDownloadPending,
		ITEM_STATE_DISABLED_LOCALLY = k_EItemStateDisabledLocally
	};
	enum ItemStatistic {
		ITEM_STATISTIC_NUM_SUBSCRIPTIONS = k_EItemStatistic_NumSubscriptions,
		ITEM_STATISTIC_NUM_FAVORITES = k_EItemStatistic_NumFavorites,
		ITEM_STATISTIC_NUM_FOLLOWERS = k_EItemStatistic_NumFollowers,
		ITEM_STATISTIC_NUM_UNIQUE_SUBSCRIPTIONS = k_EItemStatistic_NumUniqueSubscriptions,
		ITEM_STATISTIC_NUM_UNIQUE_FAVORITES = k_EItemStatistic_NumUniqueFavorites,
		ITEM_STATISTIC_NUM_UNIQUE_FOLLOWERS = k_EItemStatistic_NumUniqueFollowers,
		ITEM_STATISTIC_NUM_UNIQUE_WEBSITE_VIEWS = k_EItemStatistic_NumUniqueWebsiteViews,
		ITEM_STATISTIC_REPORT_SCORE = k_EItemStatistic_ReportScore,
		ITEM_STATISTIC_NUM_SECONDS_PLAYED = k_EItemStatistic_NumSecondsPlayed,
		ITEM_STATISTIC_NUM_PLAYTIME_SESSIONS = k_EItemStatistic_NumPlaytimeSessions,
		ITEM_STATISTIC_NUM_COMMENTS = k_EItemStatistic_NumComments,
		ITEM_STATISTIC_NUM_SECONDS_PLAYED_DURING_TIME_PERIOD = k_EItemStatistic_NumSecondsPlayedDuringTimePeriod,
		ITEM_STATISTIC_NUM_PLAYTIME_SESSIONS_DURING_TIME_PERIOD = k_EItemStatistic_NumPlaytimeSessionsDuringTimePeriod
	};
	enum ItemUpdateStatus {
		ITEM_UPDATE_STATUS_INVALID = k_EItemUpdateStatusInvalid,
		ITEM_UPDATE_STATUS_PREPARING_CONFIG = k_EItemUpdateStatusPreparingConfig,
		ITEM_UPDATE_STATUS_PREPARING_CONTENT = k_EItemUpdateStatusPreparingContent,
		ITEM_UPDATE_STATUS_UPLOADING_CONTENT = k_EItemUpdateStatusUploadingContent,
		ITEM_UPDATE_STATUS_UPLOADING_PREVIEW_FILE = k_EItemUpdateStatusUploadingPreviewFile,
		ITEM_UPDATE_STATUS_COMMITTING_CHANGES = k_EItemUpdateStatusCommittingChanges
	};
	enum UGCContentDescriptorID {
		UGC_CONTENT_DESCRIPTOR_NUDITY_OR_SEXUAL_CONTENT = k_EUGCContentDescriptor_NudityOrSexualContent,
		UGC_CONTENT_DESCRIPTOR_FREQUENT_VIOLENCE_OR_GORE = k_EUGCContentDescriptor_FrequentViolenceOrGore,
		UGC_CONTENT_DESCRIPTOR_ADULT_ONLY_SEXUAL_CONTENT = k_EUGCContentDescriptor_AdultOnlySexualContent,
		UGC_CONTENT_DESCRIPTOR_GRATUITOUS_SEXUAL_CONTENT = k_EUGCContentDescriptor_GratuitousSexualContent,
		UGC_CONTENT_DESCRIPTOR_ANY_MATURE_CONTENT = k_EUGCContentDescriptor_AnyMatureContent
	};
	enum UGCMatchingUGCType {
		UGC_MATCHING_UGC_TYPE_ITEMS = k_EUGCMatchingUGCType_Items,
		UGC_MATCHING_UGC_TYPE_ITEMS_MTX = k_EUGCMatchingUGCType_Items_Mtx,
		UGC_MATCHING_UGC_TYPE_ITEMS_READY_TO_USE = k_EUGCMatchingUGCType_Items_ReadyToUse,
		UGC_MATCHING_UGC_TYPE_COLLECTIONS = k_EUGCMatchingUGCType_Collections,
		UGC_MATCHING_UGC_TYPE_ARTWORK = k_EUGCMatchingUGCType_Artwork,
		UGC_MATCHING_UGC_TYPE_VIDEOS = k_EUGCMatchingUGCType_Videos,
		UGC_MATCHING_UGC_TYPE_SCREENSHOTS = k_EUGCMatchingUGCType_Screenshots,
		UGC_MATCHING_UGC_TYPE_ALL_GUIDES = k_EUGCMatchingUGCType_AllGuides,
		UGC_MATCHING_UGC_TYPE_WEB_GUIDES = k_EUGCMatchingUGCType_WebGuides,
		UGC_MATCHING_UGC_TYPE_INTEGRATED_GUIDES = k_EUGCMatchingUGCType_IntegratedGuides,
		UGC_MATCHING_UGC_TYPE_USABLE_IN_GAME = k_EUGCMatchingUGCType_UsableInGame,
		UGC_MATCHING_UGC_TYPE_CONTROLLER_BINDINGS = k_EUGCMatchingUGCType_ControllerBindings,
		UGC_MATCHING_UGC_TYPE_GAME_MANAGED_ITEMS = k_EUGCMatchingUGCType_GameManagedItems,
		UGC_MATCHING_UGC_TYPE_ALL = k_EUGCMatchingUGCType_All
	};
	enum UGCQuery {
		UGC_QUERY_RANKED_BY_VOTE = k_EUGCQuery_RankedByVote,
		UGC_QUERY_RANKED_BY_PUBLICATION_DATE = k_EUGCQuery_RankedByPublicationDate,
		UGC_QUERY_ACCEPTED_FOR_GAME_RANKED_BY_ACCEPTANCE_DATE = k_EUGCQuery_AcceptedForGameRankedByAcceptanceDate,
		UGC_QUERY_RANKED_BY_TREND = k_EUGCQuery_RankedByTrend,
		UGC_QUERY_FAVORITED_BY_FRIENDS_RANKED_BY_PUBLICATION_DATE = k_EUGCQuery_FavoritedByFriendsRankedByPublicationDate,
		UGC_QUERY_CREATED_BY_FRIENDS_RANKED_BY_PUBLICATION_DATE = k_EUGCQuery_CreatedByFriendsRankedByPublicationDate,
		UGC_QUERY_RANKED_BY_NUM_TIMES_REPORTED = k_EUGCQuery_RankedByNumTimesReported,
		UGC_QUERY_CREATED_BY_FOLLOWED_USERS_RANKED_BY_PUBLICATION_DATE = k_EUGCQuery_CreatedByFollowedUsersRankedByPublicationDate,
		UGC_QUERY_NOT_YET_RATED = k_EUGCQuery_NotYetRated,
		UGC_QUERY_RANKED_BY_TOTAL_VOTES_ASC = k_EUGCQuery_RankedByTotalVotesAsc,
		UGC_QUERY_RANKED_BY_VOTES_UP = k_EUGCQuery_RankedByVotesUp,
		UGC_QUERY_RANKED_BY_TEXT_SEARCH = k_EUGCQuery_RankedByTextSearch,
		UGC_QUERY_RANKED_BY_TOTAL_UNIQUE_SUBSCRIPTIONS = k_EUGCQuery_RankedByTotalUniqueSubscriptions,
		UGC_QUERY_RANKED_BY_PLAYTIME_TREND = k_EUGCQuery_RankedByPlaytimeTrend,
		UGC_QUERY_RANKED_BY_TOTAL_PLAYTIME = k_EUGCQuery_RankedByTotalPlaytime,
		UGC_QUERY_RANKED_BY_AVERAGE_PLAYTIME_TREND = k_EUGCQuery_RankedByAveragePlaytimeTrend,
		UGC_QUERY_RANKED_BY_LIFETIME_AVERAGE_PLAYTIME = k_EUGCQuery_RankedByLifetimeAveragePlaytime,
		UGC_QUERY_RANKED_BY_PLAYTIME_SESSIONS_TREND = k_EUGCQuery_RankedByPlaytimeSessionsTrend,
		UGC_QUERY_RANKED_BY_LIFETIME_PLAYTIME_SESSIONS = k_EUGCQuery_RankedByLifetimePlaytimeSessions,
		UGC_QUERY_RANKED_BY_LAST_UPDATED_DATE = k_EUGCQuery_RankedByLastUpdatedDate
	};
	enum UserUGCList {
		USER_UGC_LIST_PUBLISHED = k_EUserUGCList_Published,
		USER_UGC_LIST_VOTED_ON = k_EUserUGCList_VotedOn,
		USER_UGC_LIST_VOTED_UP = k_EUserUGCList_VotedUp,
		USER_UGC_LIST_VOTED_DOWN = k_EUserUGCList_VotedDown,
		USER_UGC_LIST_WILL_VOTE_LATER = k_EUserUGCList_WillVoteLater,
		USER_UGC_LIST_FAVORITED = k_EUserUGCList_Favorited,
		USER_UGC_LIST_SUBSCRIBED = k_EUserUGCList_Subscribed,
		USER_UGC_LIST_USED_OR_PLAYED = k_EUserUGCList_UsedOrPlayed,
		USER_UGC_LIST_FOLLOWED = k_EUserUGCList_Followed
	};
	enum UserUGCListSortOrder {
		USER_UGC_LIST_SORT_ORDER_CREATION_ORDER_DESC = k_EUserUGCListSortOrder_CreationOrderDesc,
		USER_UGC_LIST_SORT_ORDER_CREATION_ORDER_ASC = k_EUserUGCListSortOrder_CreationOrderAsc,
		USER_UGC_LIST_SORT_ORDER_TITLE_ASC = k_EUserUGCListSortOrder_TitleAsc,
		USER_UGC_LIST_SORT_ORDER_LAST_UPDATED_DESC = k_EUserUGCListSortOrder_LastUpdatedDesc,
		USER_UGC_LIST_SORT_ORDER_SUBSCRIPTION_DATE_DESC = k_EUserUGCListSortOrder_SubscriptionDateDesc,
		USER_UGC_LIST_SORT_ORDER_VOTE_SCORE_DESC = k_EUserUGCListSortOrder_VoteScoreDesc,
		USER_UGC_LIST_SORT_ORDER_FOR_MODERATION = k_EUserUGCListSortOrder_ForModeration
	};


	// STEAMWORKS FUNCTIONS
	/////////////////////////////////////////
	//
	// Main /////////////////////////////////
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
	bool serverInit(const String& ip, int game_port, int query_port, ServerMode server_mode, const String& version_number);
	Dictionary serverInitEx(const String& ip, int game_port, int query_port, ServerMode server_mode, const String& version_number);
	void serverReleaseCurrentThreadMemory();
	void serverShutdown();
	void steamworksError(const String& failed_signal);

	// Game Server //////////////////////////
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
	Dictionary handleIncomingPacket(int packet, const String& ip, int port);
	bool loggedOn();
	void logOff();
	void logOn(const String& token);
	void logOnAnonymous();
	bool requestUserGroupStatus(uint64_t steam_id, int group_id);
	bool secure();
	void setAdvertiseServerActive(bool active);
	void setBotPlayerCount(int bots);
	void setDedicatedServer(bool dedicated);
	void setGameData(const String& data);
	void setGameDescription(const String& description);
	void setGameTags(const String& tags);
	void setKeyValue(const String& key, const String& value);
	void setMapName(const String& map);
	void setMaxPlayerCount(int players_max);
	void setModDir(const String& mod_directory);
	void setPasswordProtected(bool password_protected);
	void setProduct(const String& product);
	void setRegion(const String& region);
	void setServerName(const String& name);
	void setSpectatorPort(int port);
	void setSpectatorServerName(const String& name);
	int userHasLicenceForApp(uint64_t steam_id, uint32 app_id);
	bool wasRestartRequested();

	// Game Server Stats ////////////////////
	bool clearUserAchievement(uint64_t steam_id, const String& name);
	Dictionary getUserAchievement(uint64_t steam_id, const String& name);
	uint32_t getUserStatInt(uint64_t steam_id, const String& name);
	float getUserStatFloat(uint64_t steam_id, const String& name);
	void requestUserStats(uint64_t steam_id);
	bool setUserAchievement(uint64_t steam_id, const String& name);
	bool setUserStatInt(uint64_t steam_id, const String& name, int32 stat);
	bool setUserStatFloat(uint64_t steam_id, const String& name, float stat);
	void storeUserStats(uint64_t steam_id);
	bool updateUserAvgRateStat(uint64_t steam_id, const String& name, float this_session, double session_length);

	// HTTP /////////////////////////////////
	uint32_t createCookieContainer(bool allow_responses_to_modify);
	uint32_t createHTTPRequest(HTTPMethod request_method, const String& absolute_url);
	bool deferHTTPRequest(uint32 request_handle);
	float getHTTPDownloadProgressPct(uint32 request_handle);
	bool getHTTPRequestWasTimedOut(uint32 request_handle);
	PackedByteArray getHTTPResponseBodyData(uint32 request_handle, uint32 buffer_size);
	uint32 getHTTPResponseBodySize(uint32 request_handle);
	uint32 getHTTPResponseHeaderSize(uint32 request_handle, const String& header_name);
	uint8 getHTTPResponseHeaderValue(uint32 request_handle, const String& header_name, uint32 buffer_size);
	uint8 getHTTPStreamingResponseBodyData(uint32 request_handle, uint32 offset, uint32 buffer_size);
	bool prioritizeHTTPRequest(uint32 request_handle);
	bool releaseCookieContainer(uint32 cookie_handle);
	bool releaseHTTPRequest(uint32 request_handle);
	bool sendHTTPRequest(uint32 request_handle);
	bool sendHTTPRequestAndStreamResponse(uint32 request_handle);
	bool setHTTPCookie(uint32 cookie_handle, const String& host, const String& url, const String& cookie);
	bool setHTTPRequestAbsoluteTimeoutMS(uint32 request_handle, uint32 milliseconds);
	bool setHTTPRequestContextValue(uint32 request_handle, uint64_t context_value);
	bool setHTTPRequestCookieContainer(uint32 request_handle, uint32 cookie_handle);
	bool setHTTPRequestGetOrPostParameter(uint32 request_handle, const String& name, const String& value);
	bool setHTTPRequestHeaderValue(uint32 request_handle, const String& header_name, const String& header_value);
	bool setHTTPRequestNetworkActivityTimeout(uint32 request_handle, uint32 timeout_seconds);
	uint8 setHTTPRequestRawPostBody(uint32 request_handle, const String& content_type, uint32 body_length);
	bool setHTTPRequestRequiresVerifiedCertificate(uint32 request_handle, bool require_verified_certificate);
	bool setHTTPRequestUserAgentInfo(uint32 request_handle, const String& user_agent_info);

	// Inventory ////////////////////////////
	int32 addPromoItem(uint32 item);
	int32 addPromoItems(PackedInt64Array items);
	bool checkResultSteamID(uint64_t steam_id_expected, int32 this_inventory_handle = 0);
	int32 consumeItem(uint64_t item_consume, uint32 quantity);
	int32 deserializeResult(PackedByteArray buffer);
	void destroyResult(int32 this_inventory_handle = 0);
	int32 exchangeItems(const PackedInt64Array output_items, const PackedInt32Array output_quantity, const PackedInt64Array input_items, const PackedInt32Array input_quantity);
	int32 generateItems(const PackedInt64Array items, const PackedInt32Array quantity);
	int32 getAllItems();
	String getItemDefinitionProperty(uint32 definition, const String& name);
	int32 getItemsByID(const PackedInt64Array id_array);
	Dictionary getItemPrice(uint32 definition);
	Array getItemsWithPrices();
	String getResultItemProperty(uint32 index, const String& name, int32 this_inventory_handle = 0);
	Array getResultItems(int32 this_inventory_handle = 0);
	Result getResultStatus(int32 this_inventory_handle = 0);
	uint32 getResultTimestamp(int32 this_inventory_handle = 0);
	int32 grantPromoItems();
	bool loadItemDefinitions();
	void requestEligiblePromoItemDefinitionsIDs(uint64_t steam_id);
	void requestPrices();
	String serializeResult(int32 this_inventory_handle = 0);
	void startPurchase(const PackedInt64Array items, const PackedInt32Array quantity);
	int32 transferItemQuantity(uint64_t item_id, uint32 quantity, uint64_t item_destination, bool split);
	int32 triggerItemDrop(uint32 definition);
	void startUpdateProperties();
	int32 submitUpdateProperties(uint64_t this_inventory_update_handle = 0);
	bool removeProperty(uint64_t item_id, const String& name, uint64_t this_inventory_update_handle = 0);
	bool setPropertyString(uint64_t item_id, const String& name, const String& value, uint64_t this_inventory_update_handle = 0);
	bool setPropertyBool(uint64_t item_id, const String& name, bool value, uint64_t this_inventory_update_handle = 0);
	bool setPropertyInt(uint64_t item_id, const String& name, uint64_t value, uint64_t this_inventory_update_handle = 0);
	bool setPropertyFloat(uint64_t item_id, const String& name, float value, uint64_t this_inventory_update_handle = 0);

	// Networking ///////////////////////////
	bool acceptP2PSessionWithUser(uint64_t remote_steam_id);
	bool allowP2PPacketRelay(bool allow);
	bool closeP2PChannelWithUser(uint64_t remote_steam_id, int channel);
	bool closeP2PSessionWithUser(uint64_t remote_steam_id);
	Dictionary getP2PSessionState(uint64_t remote_steam_id);
	uint32_t getAvailableP2PPacketSize(int channel = 0);
	Dictionary readP2PPacket(uint32_t packet, int channel = 0);
	bool sendP2PPacket(uint64_t remote_steam_id, const PackedByteArray data, P2PSend send_type, int channel = 0);

	// Networking Messages //////////////////
	bool acceptSessionWithUser(uint64_t remote_steam_id);
	bool closeChannelWithUser(uint64_t remote_steam_id, int channel);
	bool closeSessionWithUser(uint64_t remote_steam_id);
	Dictionary getSessionConnectionInfo(uint64_t remote_steam_id, bool get_connection, bool get_status);
	Array receiveMessagesOnChannel(int channel, int max_messages);
	int sendMessageToUser(uint64_t remote_steam_id, const PackedByteArray data, int flags, int channel);
	
	// Networking Sockets ///////////////////
	int acceptConnection(uint32 connection_handle);
	bool beginAsyncRequestFakeIP(int num_ports);
	bool closeConnection(uint32 peer, int reason, const String& debug_message, bool linger);
	bool closeListenSocket(uint32 socket);
	int configureConnectionLanes(uint32 connection, int lanes, Array priorities, Array weights);
	uint32 connectP2P(uint64_t remote_steam_id, int virtual_port, Array options);
	uint32 connectByIPAddress(const String& ip_address_with_port, Array options);
	uint32 connectToHostedDedicatedServer(uint64_t remote_steam_id, int virtual_port, Array options);
	void createFakeUDPPort(int fake_server_port);
	uint32 createHostedDedicatedServerListenSocket(int virtual_port, Array options);
	uint32 createListenSocketIP(const String& ip_address, Array options);
	uint32 createListenSocketP2P(int virtual_port, Array options);
	uint32 createListenSocketP2PFakeIP(int fake_port, Array options);
	uint32 createPollGroup();
	Dictionary createSocketPair(bool loopback, uint64_t remote_steam_id1, uint64_t remote_steam_id2);
	bool destroyPollGroup(uint32 poll_group);
//		int findRelayAuthTicketForServer(int port);	<------ Uses datagram relay structs which were removed from base SDK
	int flushMessagesOnConnection(uint32 connection_handle);
	NetworkingAvailability getAuthenticationStatus();
	Dictionary getCertificateRequest();
	Dictionary getConnectionInfo(uint32 connection_handle);
	String getConnectionName(uint32 peer);
	Dictionary getConnectionRealTimeStatus(uint32 connection_handle, int lanes, bool get_status = true);
	uint64_t getConnectionUserData(uint32 peer);
	Dictionary getDetailedConnectionStatus(uint32 connection_handle);
	Dictionary getFakeIP(int first_port = 0);
//		int getGameCoordinatorServerLogin(const String& app_data);	<------ Uses datagram relay structs which were removed from base SDK
//		int getHostedDedicatedServerAddress();	<------ Uses datagram relay structs which were removed from base SDK
	uint32 getHostedDedicatedServerPOPId();
	int getHostedDedicatedServerPort();
	String getListenSocketAddress(uint32 socket, bool with_port = true);
	Dictionary getRemoteFakeIPForConnection(uint32 connection);
	NetworkingAvailability initAuthentication();
	Array receiveMessagesOnConnection(uint32 connection, int max_messages);
	Array receiveMessagesOnPollGroup(uint32 poll_group, int max_messages);
//		Dictionary receivedRelayAuthTicket();	<------ Uses datagram relay structs which were removed from base SDK
	void resetIdentity(uint64_t remote_steam_id);
	void runNetworkingCallbacks();
	void sendMessages(int messages, const PackedByteArray data, uint32 connection_handle, int flags);
	Dictionary sendMessageToConnection(uint32 connection_handle, const PackedByteArray data, int flags);
	Dictionary setCertificate(const PackedByteArray& certificate);		
	bool setConnectionPollGroup(uint32 connection_handle, uint32 poll_group);
	void setConnectionName(uint32 peer, const String& name);

	// Networking Utils /////////////////////
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
	Dictionary parsePingLocationString(const String& location_string);
	bool setConnectionConfigValueFloat(uint32 connection, NetworkingConfigValue config, float value);
	bool setConnectionConfigValueInt32(uint32 connection, NetworkingConfigValue config, int32 value);
	bool setConnectionConfigValueString(uint32 connection, NetworkingConfigValue config, const String& value);
//		bool setConfigValue(NetworkingConfigValue setting, NetworkingConfigScope scope_type, uint32_t connection_handle, NetworkingConfigDataType data_type, auto value);
	bool setGlobalConfigValueFloat(NetworkingConfigValue config, float value);
	bool setGlobalConfigValueInt32(NetworkingConfigValue config, int32 value);
	bool setGlobalConfigValueString(NetworkingConfigValue config, const String& value);

	// UGC //////////////////////////////////
	void addAppDependency(uint64_t published_file_id, uint32_t app_id);
	bool addContentDescriptor(uint64_t update_handle, int descriptor_id);
	void addDependency(uint64_t published_file_id, uint64_t child_published_file_id);
	bool addExcludedTag(uint64_t query_handle, const String& tag_name);
	bool addItemKeyValueTag(uint64_t query_handle, const String& key, const String& value);
	bool addItemPreviewFile(uint64_t query_handle, const String& preview_file, ItemPreviewType type);
	bool addItemPreviewVideo(uint64_t query_handle, const String& video_id);
	void addItemToFavorites(uint32_t app_id, uint64_t published_file_id);
	bool addRequiredKeyValueTag(uint64_t query_handle, const String& key, const String& value);
	bool addRequiredTag(uint64_t query_handle, const String& tag_name);
	bool addRequiredTagGroup(uint64_t query_handle, Array tag_array);
	bool initWorkshopForGameServer(uint32_t workshop_depot_id);
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
	Array getUserContentDescriptorPreferences(uint32 max_entries);
	void getUserItemVote(uint64_t published_file_id);
	bool releaseQueryUGCRequest(uint64_t query_handle);
	void removeAppDependency(uint64_t published_file_id, uint32_t app_id);
	bool removeContentDescriptor(uint64_t update_handle, int descriptor_id);
	void removeDependency(uint64_t published_file_id, uint64_t child_published_file_id);
	void removeItemFromFavorites(uint32_t app_id, uint64_t published_file_id);
	bool removeItemKeyValueTags(uint64_t update_handle, const String& key);
	bool removeItemPreview(uint64_t update_handle, uint32 index);
	void sendQueryUGCRequest(uint64_t update_handle);
	bool setAllowCachedResponse(uint64_t update_handle, uint32 max_age_seconds);
	bool setCloudFileNameFilter(uint64_t update_handle, const String& match_cloud_filename);
	bool setItemContent(uint64_t update_handle, const String& content_folder);
	bool setItemDescription(uint64_t update_handle, const String& description);
	bool setItemMetadata(uint64_t update_handle, const String& ugc_metadata);
	bool setItemPreview(uint64_t update_handle, const String& preview_file);
	bool setItemTags(uint64_t update_handle, Array tag_array, bool allow_admin_tags = false);
	bool setItemTitle(uint64_t update_handle, const String& title);
	bool setItemUpdateLanguage(uint64_t update_handle, const String& language);
	bool setItemVisibility(uint64_t update_handle, RemoteStoragePublishedFileVisibility visibility);
	bool setLanguage(uint64_t query_handle, const String& language);
	bool setMatchAnyTag(uint64_t query_handle, bool match_any_tag);
	bool setRankedByTrendDays(uint64_t query_handle, uint32 days);
	bool setReturnAdditionalPreviews(uint64_t query_handle, bool return_additional_previews);
	bool setReturnChildren(uint64_t query_handle, bool return_children);
	bool setReturnKeyValueTags(uint64_t query_handle, bool return_key_value_tags);
	bool setReturnLongDescription(uint64_t query_handle, bool return_long_description);
	bool setReturnMetadata(uint64_t query_handle, bool return_metadata);
	bool setReturnOnlyIDs(uint64_t query_handle, bool return_only_ids);
	bool setReturnPlaytimeStats(uint64_t query_handle, uint32 days);
	bool setReturnTotalOnly(uint64_t query_handle, bool return_total_only);
	bool setSearchText(uint64_t query_handle, const String& search_text);
	void setUserItemVote(uint64_t published_file_id, bool vote_up);
	uint64_t startItemUpdate(uint32_t app_id, uint64_t file_id);
	void startPlaytimeTracking(Array published_file_ids);
	void stopPlaytimeTracking(Array published_file_ids);
	void stopPlaytimeTrackingForAllItems();
	void getAppDependencies(uint64_t published_file_id);
	void submitItemUpdate(uint64_t update_handle, const String& change_note);
	void subscribeItem(uint64_t published_file_id);
	void suspendDownloads(bool suspend);
	void unsubscribeItem(uint64_t published_file_id);
	bool updateItemPreviewFile(uint64_t update_handle, uint32 index, const String& preview_file);
	bool updateItemPreviewVideo(uint64_t update_handle, uint32 index, const String& video_id);
	bool showWorkshopEULA();
	void getWorkshopEULAStatus();
	bool setTimeCreatedDateRange(uint64_t update_handle, uint32 start, uint32 end);
	bool setTimeUpdatedDateRange(uint64_t update_handle, uint32 start, uint32 end);

protected:
	static void _bind_methods();
	static SteamServer *singleton;

private:
	// Main
	bool is_init_success;

	const SteamNetworkingConfigValue_t *convertOptionsArray(Array options);
	CSteamID createSteamID(uint64_t steam_id, AccountType account_type = AccountType(-1));
	SteamNetworkingIdentity getIdentityFromSteamID(uint64_t steam_id);
	uint32 getIPFromSteamIP(SteamNetworkingIPAddr this_address);
	uint32 getIPv4FromString(String ip_string);
	uint32 getIPFromString(String ip_string);
	uint64_t getSteamIDFromIdentity(SteamNetworkingIdentity this_identity);
	SteamNetworkingIPAddr getSteamIPFromInt(uint32 ip_integer);
	SteamNetworkingIPAddr getSteamIPFromString(String ip_string);
	String getStringFromIP(uint32 ip_address);
	String getStringFromSteamIP(SteamNetworkingIPAddr this_address);

	// Inventory
	SteamInventoryUpdateHandle_t inventory_update_handle;
	SteamInventoryResult_t inventory_handle;
	SteamItemDetails_t inventory_details;

	// Networking Sockets
	uint32 network_connection;
	uint32 network_poll_group;
	uint64_t networking_microseconds = 0;
//		SteamDatagramHostedAddress hosted_address;
	PackedByteArray routing_blob;
//		SteamDatagramRelayAuthTicket relay_auth_ticket;

	// Run the Steamworks server API callbacks
	void run_callbacks(){
		SteamGameServer_RunCallbacks();
	}


	// STEAM SERVER CALLBACKS
	/////////////////////////////////////////
	//
	// Game Server callbacks ////////////////
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

	// Game Server Stat callbacks ///////////
	STEAM_GAMESERVER_CALLBACK(SteamServer, stats_stored, GSStatsStored_t, callbackStatsStored);
	STEAM_GAMESERVER_CALLBACK(SteamServer, stats_unloaded, GSStatsUnloaded_t, callbackStatsUnloaded);

	// HTTP callbacks ///////////////////////
	STEAM_GAMESERVER_CALLBACK(SteamServer, http_request_completed, HTTPRequestCompleted_t, callbackHTTPRequestCompleted);
	STEAM_GAMESERVER_CALLBACK(SteamServer, http_request_data_received, HTTPRequestDataReceived_t, callbackHTTPRequestDataReceived);
	STEAM_GAMESERVER_CALLBACK(SteamServer, http_request_headers_received, HTTPRequestHeadersReceived_t, callbackHTTPRequestHeadersReceived);

	// Inventory callbacks //////////////////
	STEAM_GAMESERVER_CALLBACK(SteamServer, inventory_definition_update, SteamInventoryDefinitionUpdate_t, callbackInventoryDefinitionUpdate);
	STEAM_GAMESERVER_CALLBACK(SteamServer, inventory_full_update, SteamInventoryFullUpdate_t, callbackInventoryFullUpdate);
	STEAM_GAMESERVER_CALLBACK(SteamServer, inventory_result_ready, SteamInventoryResultReady_t, callbackInventoryResultReady);

	// Networking callbacks /////////////////
	STEAM_GAMESERVER_CALLBACK(SteamServer, p2p_session_connect_fail, P2PSessionConnectFail_t, callbackP2PSessionConnectFail);
	STEAM_GAMESERVER_CALLBACK(SteamServer, p2p_session_request, P2PSessionRequest_t, callbackP2PSessionRequest);

	// Networking Messages callbacks ////////
	STEAM_GAMESERVER_CALLBACK(SteamServer, network_messages_session_request, SteamNetworkingMessagesSessionRequest_t, callbackNetworkMessagesSessionRequest);
	STEAM_GAMESERVER_CALLBACK(SteamServer, network_messages_session_failed, SteamNetworkingMessagesSessionFailed_t, callbackNetworkMessagesSessionFailed);

	// Networking Sockets callbacks /////////
	STEAM_GAMESERVER_CALLBACK(SteamServer, network_connection_status_changed, SteamNetConnectionStatusChangedCallback_t, callbackNetworkConnectionStatusChanged);
	STEAM_GAMESERVER_CALLBACK(SteamServer, network_authentication_status, SteamNetAuthenticationStatus_t, callbackNetworkAuthenticationStatus);
	STEAM_GAMESERVER_CALLBACK(SteamServer, fake_ip_result, SteamNetworkingFakeIPResult_t, callbackNetworkingFakeIPResult);

	// Networking Utils callbacks ///////////
	STEAM_GAMESERVER_CALLBACK(SteamServer, relay_network_status, SteamRelayNetworkStatus_t, callbackRelayNetworkStatus);

	// Remote Storage callbacks /////////////
	STEAM_GAMESERVER_CALLBACK(SteamServer, local_file_changed, RemoteStorageLocalFileChange_t, callbackLocalFileChanged);

	// UGC callbacks ////////////////////////
	STEAM_GAMESERVER_CALLBACK(SteamServer, item_downloaded, DownloadItemResult_t, callbackItemDownloaded);
	STEAM_GAMESERVER_CALLBACK(SteamServer, item_installed, ItemInstalled_t, callbackItemInstalled);
	STEAM_GAMESERVER_CALLBACK(SteamServer, user_subscribed_items_list_changed, UserSubscribedItemsListChanged_t, callbackUserSubscribedItemsListChanged);


	// STEAM CALL RESULTS
	/////////////////////////////////////////
	//
	// Game Server Stats call results ///////
	CCallResult<SteamServer, GSStatsReceived_t> callResultStatReceived;
	void stats_received(GSStatsReceived_t *call_data, bool io_failure);

	// Inventory call results ///////////////
	CCallResult<SteamServer, SteamInventoryEligiblePromoItemDefIDs_t> callResultEligiblePromoItemDefIDs;
	void inventory_eligible_promo_item(SteamInventoryEligiblePromoItemDefIDs_t *call_data, bool io_failure);
	CCallResult<SteamServer, SteamInventoryRequestPricesResult_t> callResultRequestPrices;
	void inventory_request_prices_result(SteamInventoryRequestPricesResult_t *call_data, bool io_failure);
	CCallResult<SteamServer, SteamInventoryStartPurchaseResult_t> callResultStartPurchase;
	void inventory_start_purchase_result(SteamInventoryStartPurchaseResult_t *call_data, bool io_failure);

	// Remote Storage call results //////////
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

	// UGC call results /////////////////////
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


VARIANT_ENUM_CAST(SteamServer::AccountType);
VARIANT_ENUM_CAST(SteamServer::AuthSessionResponse);

VARIANT_ENUM_CAST(SteamServer::BeginAuthSessionResult);

VARIANT_ENUM_CAST(SteamServer::DenyReason);

VARIANT_ENUM_CAST(SteamServer::FilePathType);

VARIANT_ENUM_CAST(SteamServer::GameIDType);

VARIANT_ENUM_CAST(SteamServer::HTTPMethod);
VARIANT_ENUM_CAST(SteamServer::HTTPStatusCode);

VARIANT_ENUM_CAST(SteamServer::IPType);
VARIANT_BITFIELD_CAST(SteamServer::ItemFlags);
VARIANT_ENUM_CAST(SteamServer::ItemPreviewType);
VARIANT_BITFIELD_CAST(SteamServer::ItemState);
VARIANT_ENUM_CAST(SteamServer::ItemStatistic);
VARIANT_ENUM_CAST(SteamServer::ItemUpdateStatus);

VARIANT_ENUM_CAST(SteamServer::LocalFileChange);

VARIANT_ENUM_CAST(SteamServer::NetworkingAvailability);
VARIANT_ENUM_CAST(SteamServer::NetworkingConfigDataType);
VARIANT_ENUM_CAST(SteamServer::NetworkingConfigScope);
VARIANT_ENUM_CAST(SteamServer::NetworkingConfigValue);
VARIANT_ENUM_CAST(SteamServer::NetworkingConnectionEnd);
VARIANT_ENUM_CAST(SteamServer::NetworkingConnectionState);
VARIANT_ENUM_CAST(SteamServer::NetworkingFakeIPType);
VARIANT_ENUM_CAST(SteamServer::NetworkingGetConfigValueResult);
VARIANT_ENUM_CAST(SteamServer::NetworkingIdentityType);
VARIANT_ENUM_CAST(SteamServer::NetworkingSocketsDebugOutputType);

VARIANT_ENUM_CAST(SteamServer::P2PSend);
VARIANT_ENUM_CAST(SteamServer::P2PSessionError);

VARIANT_BITFIELD_CAST(SteamServer::RemoteStoragePlatform);
VARIANT_ENUM_CAST(SteamServer::RemoteStoragePublishedFileVisibility);
VARIANT_ENUM_CAST(SteamServer::Result);

VARIANT_ENUM_CAST(SteamServer::ServerMode);
VARIANT_ENUM_CAST(SteamServer::SocketConnectionType);
VARIANT_ENUM_CAST(SteamServer::SocketState);
VARIANT_ENUM_CAST(SteamServer::SteamAPIInitResult);

VARIANT_ENUM_CAST(SteamServer::UGCContentDescriptorID);
VARIANT_ENUM_CAST(SteamServer::UGCMatchingUGCType);
VARIANT_ENUM_CAST(SteamServer::UGCQuery);
VARIANT_ENUM_CAST(SteamServer::UGCReadAction);
VARIANT_ENUM_CAST(SteamServer::Universe);
VARIANT_ENUM_CAST(SteamServer::UserUGCList);
VARIANT_ENUM_CAST(SteamServer::UserUGCListSortOrder);

VARIANT_ENUM_CAST(SteamServer::WorkshopEnumerationType);
VARIANT_ENUM_CAST(SteamServer::WorkshopFileAction);
VARIANT_ENUM_CAST(SteamServer::WorkshopFileType);
VARIANT_ENUM_CAST(SteamServer::WorkshopVideoProvider);
VARIANT_ENUM_CAST(SteamServer::WorkshopVote);


#endif // GODOTSTEAM_SERVER_H