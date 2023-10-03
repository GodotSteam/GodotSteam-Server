#include "register_types.h"

#include <gdextension_interface.h>

#include <godot_cpp/core/defs.hpp>
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/classes/engine.hpp>
#include <godot_cpp/godot.hpp>

#include "godotsteam_server.h"

using namespace godot;

static SteamServer *SteamServerPtr;

void initialize_godotsteam_server(ModuleInitializationLevel level){
	if(level == MODULE_INITIALIZATION_LEVEL_SCENE){
		ClassDB::register_class<SteamServer>();
		SteamServerPtr = memnew(SteamServer);
		Engine::get_singleton()->register_singleton("SteamServer", SteamServer::get_singleton());
	}
}

void uninitialize_godotsteam_server(ModuleInitializationLevel level){
	if(level == MODULE_INITIALIZATION_LEVEL_SCENE){
		Engine::get_singleton()->unregister_singleton("SteamServer");
		memdelete(SteamServerPtr);
	}
}

extern "C" {
	GDExtensionBool GDE_EXPORT godotsteam_server_init(GDExtensionInterfaceGetProcAddress p_interface, const GDExtensionClassLibraryPtr p_library, GDExtensionInitialization *r_initialization){
		godot::GDExtensionBinding::InitObject init_obj(p_interface, p_library, r_initialization);

		init_obj.register_initializer(initialize_godotsteam_server);
		init_obj.register_terminator(uninitialize_godotsteam_server);
		init_obj.set_minimum_library_initialization_level(MODULE_INITIALIZATION_LEVEL_SCENE);

		return init_obj.init();
	}
}