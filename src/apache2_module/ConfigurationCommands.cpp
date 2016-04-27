/*
 *  Phusion Passenger - https://www.phusionpassenger.com/
 *  Copyright (c) 2010-2015 Phusion Holding B.V.
 *
 *  "Passenger", "Phusion Passenger" and "Union Station" are registered
 *  trademarks of Phusion Holding B.V.
 *
 *  See LICENSE file for license information.
 */

/*
 * ConfigurationCommands.cpp is automatically generated from ConfigurationCommands.cpp.erb,
 * using definitions from src/ruby_supportlib/phusion_passenger/apache2/config_options.rb.
 * Edits to ConfigurationCommands.cpp will be lost.
 *
 * To update ConfigurationCommands.cpp:
 *   rake apache2
 *
 * To force regeneration of ConfigurationCommands.c:
 *   rm -f src/apache2_module/ConfigurationCommands.cpp
 *   rake src/apache2_module/ConfigurationCommands.cpp
 */




	
	AP_INIT_TAKE1("PassengerRuby",
		(Take1Func) cmd_passenger_ruby,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"The Ruby interpreter to use."),

	
	AP_INIT_TAKE1("PassengerPython",
		(Take1Func) cmd_passenger_python,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"The Python interpreter to use."),

	
	AP_INIT_TAKE1("PassengerNodejs",
		(Take1Func) cmd_passenger_nodejs,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"The Node.js command to use."),

	
	AP_INIT_TAKE1("PassengerMeteorAppSettings",
		(Take1Func) cmd_passenger_meteor_app_settings,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"Settings file for (non-bundled) Meteor apps."),

	
	AP_INIT_TAKE1("PassengerAppEnv",
		(Take1Func) cmd_passenger_app_env,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"The environment under which applications are run."),

	
	AP_INIT_TAKE1("PassengerMinInstances",
		(Take1Func) cmd_passenger_min_instances,
		NULL,
		OR_LIMIT | ACCESS_CONF | RSRC_CONF,
		"The minimum number of application instances to keep when cleaning idle instances."),

	
	AP_INIT_TAKE1("PassengerMaxInstancesPerApp",
		(Take1Func) cmd_passenger_max_instances_per_app,
		NULL,
		RSRC_CONF,
		"The maximum number of simultaneously alive application instances a single application may occupy."),

	
	AP_INIT_TAKE1("PassengerUser",
		(Take1Func) cmd_passenger_user,
		NULL,
		ACCESS_CONF | RSRC_CONF,
		"The user that Ruby applications must run as."),

	
	AP_INIT_TAKE1("PassengerGroup",
		(Take1Func) cmd_passenger_group,
		NULL,
		ACCESS_CONF | RSRC_CONF,
		"The group that Ruby applications must run as."),

	
	AP_INIT_FLAG("PassengerErrorOverride",
		(FlagFunc) cmd_passenger_error_override,
		NULL,
		OR_ALL,
		"Allow Apache to handle error response."),

	
	AP_INIT_TAKE1("PassengerMaxRequests",
		(Take1Func) cmd_passenger_max_requests,
		NULL,
		OR_LIMIT | ACCESS_CONF | RSRC_CONF,
		"The maximum number of requests that an application instance may process."),

	
	AP_INIT_TAKE1("PassengerStartTimeout",
		(Take1Func) cmd_passenger_start_timeout,
		NULL,
		OR_LIMIT | ACCESS_CONF | RSRC_CONF,
		"A timeout for application startup."),

	
	AP_INIT_FLAG("PassengerHighPerformance",
		(FlagFunc) cmd_passenger_high_performance,
		NULL,
		OR_ALL,
		"Enable or disable Passenger's high performance mode."),

	
	AP_INIT_FLAG("PassengerEnabled",
		(FlagFunc) cmd_passenger_enabled,
		NULL,
		OR_ALL,
		"Enable or disable Phusion Passenger."),

	
	AP_INIT_TAKE1("PassengerMaxRequestQueueSize",
		(Take1Func) cmd_passenger_max_request_queue_size,
		NULL,
		OR_ALL,
		"The maximum number of queued requests."),

	
	AP_INIT_TAKE1("PassengerMaxPreloaderIdleTime",
		(Take1Func) cmd_passenger_max_preloader_idle_time,
		NULL,
		RSRC_CONF,
		"The maximum number of seconds that a preloader process may be idle before it is shutdown."),

	
	AP_INIT_FLAG("PassengerLoadShellEnvvars",
		(FlagFunc) cmd_passenger_load_shell_envvars,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"Whether to load environment variables from the shell before running the application."),

	
	AP_INIT_FLAG("PassengerBufferUpload",
		(FlagFunc) cmd_passenger_buffer_upload,
		NULL,
		OR_ALL,
		"Whether to buffer file uploads."),

	
	AP_INIT_TAKE1("PassengerAppType",
		(Take1Func) cmd_passenger_app_type,
		NULL,
		OR_ALL,
		"Force specific application type."),

	
	AP_INIT_TAKE1("PassengerStartupFile",
		(Take1Func) cmd_passenger_startup_file,
		NULL,
		OR_ALL,
		"Force specific startup file."),

	
	AP_INIT_FLAG("PassengerStickySessions",
		(FlagFunc) cmd_passenger_sticky_sessions,
		NULL,
		OR_ALL,
		"Whether to enable sticky sessions."),

	
	AP_INIT_FLAG("PassengerStickySessionsCookieName",
		(FlagFunc) cmd_passenger_sticky_sessions_cookie_name,
		NULL,
		OR_ALL,
		"The cookie name to use for sticky sessions."),

	
	AP_INIT_TAKE1("PassengerSpawnMethod",
		(Take1Func) cmd_passenger_spawn_method,
		NULL,
		RSRC_CONF,
		"The spawn method to use."),

	
	AP_INIT_FLAG("PassengerShowVersionInHeader",
		(FlagFunc) cmd_passenger_show_version_in_header,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"Whether to show the Phusion Passenger version number in the X-Powered-By header."),

	
	AP_INIT_FLAG("PassengerFriendlyErrorPages",
		(FlagFunc) cmd_passenger_friendly_error_pages,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"Whether to display friendly error pages when something goes wrong."),

	
	AP_INIT_TAKE1("PassengerRestartDir",
		(Take1Func) cmd_passenger_restart_dir,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"The directory in which Passenger should look for restart.txt."),

	
	AP_INIT_TAKE1("PassengerAppGroupName",
		(Take1Func) cmd_passenger_app_group_name,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"Application process group name."),

	
	AP_INIT_TAKE1("PassengerForceMaxConcurrentRequestsPerProcess",
		(Take1Func) cmd_passenger_force_max_concurrent_requests_per_process,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"Force Passenger to believe that an application process can handle the given number of concurrent requests per process"),

	
	AP_INIT_TAKE1("PassengerLveMinUid",
		(Take1Func) cmd_passenger_lve_min_uid,
		NULL,
		RSRC_CONF,
		"Minimum user id starting from which entering LVE and CageFS is allowed."),

	
	AP_INIT_TAKE1("RailsEnv",
		(Take1Func) cmd_passenger_app_env,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"The environment under which applications are run."),

	
	AP_INIT_TAKE1("RackEnv",
		(Take1Func) cmd_passenger_app_env,
		NULL,
		OR_OPTIONS | ACCESS_CONF | RSRC_CONF,
		"The environment under which applications are run."),

	
	AP_INIT_TAKE1("RailsSpawnMethod",
		(Take1Func) cmd_passenger_spawn_method,
		NULL,
		RSRC_CONF,
		"The spawn method to use."),

