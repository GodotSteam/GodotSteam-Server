#include "register_types.h"
#include "core/object/class_db.h"
#include "core/config/engine.h"
#include "godotsteam_server.h"

static SteamServer* SteamServerPtr = NULL;

void initialize_godotsteam_server_module(ModuleInitializationLevel level){
	if(level == MODULE_INITIALIZATION_LEVEL_SERVERS){
		ClassDB::register_class<SteamServer>();
		SteamServerPtr = memnew(SteamServer);
		Engine::get_singleton()->add_singleton(Engine::Singleton("SteamServer", SteamServer::get_singleton()));
	}
}

void uninitialize_godotsteam_server_module(ModuleInitializationLevel level){
	if(level == MODULE_INITIALIZATION_LEVEL_SERVERS){
		memdelete(SteamServerPtr);
	}
}
