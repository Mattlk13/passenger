/*
 *  Phusion Passenger - https://www.phusionpassenger.com/
 *  Copyright (c) 2011-2016 Phusion Holding B.V.
 *
 *  "Passenger", "Phusion Passenger" and "Union Station" are registered
 *  trademarks of Phusion Holding B.V.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */
#ifndef _PASSENGER_SPAWNING_KIT_PREPARATION_RULES_H_
#define _PASSENGER_SPAWNING_KIT_PREPARATION_RULES_H_

#include <oxt/backtrace.hpp>
#include <string>
#include <vector>
#include <cstddef>
#include <cerrno>

#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

#include <Core/SpawningKit/Options.h>
#include <Core/SpawningKit/UserSwitchingRules.h>

#include <Exceptions.h>
#include <Logging.h>
#include <Utils.h>
#include <Utils/StrIntUtils.h>

namespace Passenger {
namespace SpawningKit {

using namespace std;
using namespace boost;
using namespace oxt;


/**
 * Contains information that will be used after fork()ing but before exec()ing,
 * such as the intended app root, the UID it should switch to, the
 * groups it should assume, etc. This structure is allocated before forking
 * because after forking and before exec() it may not be safe to allocate memory.
 */
struct SpawnPreparationInfo {
	// General

	/** Absolute application root path. */
	string appRoot;
	/** Absolute pre-exec chroot path. If no chroot is configured, then this is "/". */
	string chrootDir;
	/** Absolute application root path inside the chroot. If no chroot is
	 * configured then this is is equal to appRoot. */
	string appRootInsideChroot;
	/** A list of all parent directories of the appRoot, as well as appRoot itself.
	 * The pre-exec chroot directory is included, and this list goes no futher than that.
	 * For example if appRoot is /var/jail/foo/bar/baz and the chroot is /var/jail,
	 * then this list contains:
	 *   /var/jail/foo
	 *   /var/jail/foo/bar
	 *   /var/jail/foo/bar/baz
	 */
	vector<string> appRootPaths;
	/** Same as appRootPaths, but without the chroot component. For example if
	 * appRoot is /var/jail/foo/bar/baz and the chroot is /var/jail, then this list
	 * contains:
	 *   /foo
	 *   /foo/bar
	 *   /foo/bar/baz
	 */
	vector<string> appRootPathsInsideChroot;

	UserSwitchingInfo userSwitching;

	// Other information
	string codeRevision;
};


/****** Private functions ******/

inline string _readFromRevisionFile(const SpawnPreparationInfo &info);
inline string _inferCodeRevisionFromCapistranoSymlink(const SpawnPreparationInfo &info);


inline void
_prepareChroot(SpawnPreparationInfo &info, const Options &options, const ConfigPtr &config) {
	TRACE_POINT();
	info.appRoot = absolutizePath(options.appRoot);
	if (options.preexecChroot.empty()) {
		info.chrootDir = "/";
	} else {
		info.chrootDir = absolutizePath(options.preexecChroot);
	}
	if (info.appRoot != info.chrootDir && startsWith(info.appRoot, info.chrootDir + "/")) {
		SpawnException e("Invalid configuration: '" + info.chrootDir +
			"' has been configured as the chroot jail, but the application " +
			"root directory '" + info.appRoot + "' is not a subdirectory of the " +
			"chroot directory, which it must be.");
		if (config->errorHandler != NULL) {
			config->errorHandler(config, e, options);
		}
		throw e;
	}
	if (info.appRoot == info.chrootDir) {
		info.appRootInsideChroot = "/";
	} else if (info.chrootDir == "/") {
		info.appRootInsideChroot = info.appRoot;
	} else {
		info.appRootInsideChroot = info.appRoot.substr(info.chrootDir.size());
	}
}

inline void
_prepareSwitchingWorkingDirectory(SpawnPreparationInfo &info, const Options &options) {
	vector<string> components;
	split(info.appRootInsideChroot, '/', components);
	P_ASSERT_EQ(components.front(), "");
	components.erase(components.begin());

	for (unsigned int i = 0; i < components.size(); i++) {
		string path;
		for (unsigned int j = 0; j <= i; j++) {
			path.append("/");
			path.append(components[j]);
		}
		if (path.empty()) {
			path = "/";
		}
		if (info.chrootDir == "/") {
			info.appRootPaths.push_back(path);
		} else {
			info.appRootPaths.push_back(info.chrootDir + path);
		}
		info.appRootPathsInsideChroot.push_back(path);
	}

	P_ASSERT_EQ(info.appRootPathsInsideChroot.back(), info.appRootInsideChroot);
}

inline void
_inferApplicationInfo(SpawnPreparationInfo &info) {
	info.codeRevision = _readFromRevisionFile(info);
	if (info.codeRevision.empty()) {
		info.codeRevision = _inferCodeRevisionFromCapistranoSymlink(info);
	}
}

inline string
_readFromRevisionFile(const SpawnPreparationInfo &info) {
	string filename = info.appRoot + "/REVISION";
	try {
		if (fileExists(filename)) {
			return strip(readAll(filename));
		}
	} catch (const SystemException &e) {
		P_WARN("Cannot access " << filename << ": " << e.what());
	}
	return string();
}

inline string
_inferCodeRevisionFromCapistranoSymlink(const SpawnPreparationInfo &info) {
	if (extractBaseName(info.appRoot) == "current") {
		char buf[PATH_MAX + 1];
		ssize_t ret;

		do {
			ret = readlink(info.appRoot.c_str(), buf, PATH_MAX);
		} while (ret == -1 && errno == EINTR);
		if (ret == -1) {
			if (errno == EINVAL) {
				return string();
			} else {
				int e = errno;
				P_WARN("Cannot read symlink " << info.appRoot << ": " << strerror(e));
			}
		}

		buf[ret] = '\0';
		return extractBaseName(buf);
	} else {
		return string();
	}
}


/****** Public functions ******/

inline SpawnPreparationInfo
prepareSpawn(const Options &options, const ConfigPtr &config) {
	TRACE_POINT();
	SpawnPreparationInfo info;
	_prepareChroot(info, options, config);
	info.userSwitching = prepareUserSwitching(options);
	_prepareSwitchingWorkingDirectory(info, options);
	_inferApplicationInfo(info);
	return info;
}

inline bool
shouldLoadShellEnvvars(const Options &options, const SpawnPreparationInfo &preparation) {
	if (options.loadShellEnvvars) {
		string shellName = extractBaseName(preparation.userSwitching.shell);
		return shellName == "bash" || shellName == "zsh" || shellName == "ksh";
	} else {
		return false;
	}
}


} // namespace SpawningKit
} // namespace Passenger

#endif /* _PASSENGER_SPAWNING_KIT_PREPARATION_RULES_H_ */
