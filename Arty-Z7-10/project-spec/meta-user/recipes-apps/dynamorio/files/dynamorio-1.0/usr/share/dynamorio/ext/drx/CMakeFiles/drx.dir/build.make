# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm

# Include any dependencies generated for this target.
include ext/drx/CMakeFiles/drx.dir/depend.make

# Include the progress variables for this target.
include ext/drx/CMakeFiles/drx.dir/progress.make

# Include the compile flags for this target's objects.
include ext/drx/CMakeFiles/drx.dir/flags.make

ext/drx/CMakeFiles/drx.dir/drx.c.o: ext/drx/CMakeFiles/drx.dir/flags.make
ext/drx/CMakeFiles/drx.dir/drx.c.o: /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drx/drx.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object ext/drx/CMakeFiles/drx.dir/drx.c.o"
	cd /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drx && /usr/bin/arm-linux-gnueabihf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -mthumb -march=armv7-a -fno-strict-aliasing -fno-stack-protector -fvisibility=internal -std=gnu99 -fno-unwind-tables -O3 -g3 -fno-stack-protector -nostdlib -mthumb -o CMakeFiles/drx.dir/drx.c.o   -c /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drx/drx.c

ext/drx/CMakeFiles/drx.dir/drx.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/drx.dir/drx.c.i"
	cd /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drx && /usr/bin/arm-linux-gnueabihf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -mthumb -march=armv7-a -fno-strict-aliasing -fno-stack-protector -fvisibility=internal -std=gnu99 -fno-unwind-tables -O3 -g3 -fno-stack-protector -nostdlib -mthumb -E /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drx/drx.c > CMakeFiles/drx.dir/drx.c.i

ext/drx/CMakeFiles/drx.dir/drx.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/drx.dir/drx.c.s"
	cd /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drx && /usr/bin/arm-linux-gnueabihf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -mthumb -march=armv7-a -fno-strict-aliasing -fno-stack-protector -fvisibility=internal -std=gnu99 -fno-unwind-tables -O3 -g3 -fno-stack-protector -nostdlib -mthumb -S /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drx/drx.c -o CMakeFiles/drx.dir/drx.c.s

ext/drx/CMakeFiles/drx.dir/drx.c.o.requires:

.PHONY : ext/drx/CMakeFiles/drx.dir/drx.c.o.requires

ext/drx/CMakeFiles/drx.dir/drx.c.o.provides: ext/drx/CMakeFiles/drx.dir/drx.c.o.requires
	$(MAKE) -f ext/drx/CMakeFiles/drx.dir/build.make ext/drx/CMakeFiles/drx.dir/drx.c.o.provides.build
.PHONY : ext/drx/CMakeFiles/drx.dir/drx.c.o.provides

ext/drx/CMakeFiles/drx.dir/drx.c.o.provides.build: ext/drx/CMakeFiles/drx.dir/drx.c.o


ext/drx/CMakeFiles/drx.dir/drx_buf.c.o: ext/drx/CMakeFiles/drx.dir/flags.make
ext/drx/CMakeFiles/drx.dir/drx_buf.c.o: /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drx/drx_buf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object ext/drx/CMakeFiles/drx.dir/drx_buf.c.o"
	cd /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drx && /usr/bin/arm-linux-gnueabihf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -mthumb -march=armv7-a -fno-strict-aliasing -fno-stack-protector -fvisibility=internal -std=gnu99 -fno-unwind-tables -O3 -g3 -fno-stack-protector -nostdlib -mthumb -o CMakeFiles/drx.dir/drx_buf.c.o   -c /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drx/drx_buf.c

ext/drx/CMakeFiles/drx.dir/drx_buf.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/drx.dir/drx_buf.c.i"
	cd /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drx && /usr/bin/arm-linux-gnueabihf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -mthumb -march=armv7-a -fno-strict-aliasing -fno-stack-protector -fvisibility=internal -std=gnu99 -fno-unwind-tables -O3 -g3 -fno-stack-protector -nostdlib -mthumb -E /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drx/drx_buf.c > CMakeFiles/drx.dir/drx_buf.c.i

ext/drx/CMakeFiles/drx.dir/drx_buf.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/drx.dir/drx_buf.c.s"
	cd /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drx && /usr/bin/arm-linux-gnueabihf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -mthumb -march=armv7-a -fno-strict-aliasing -fno-stack-protector -fvisibility=internal -std=gnu99 -fno-unwind-tables -O3 -g3 -fno-stack-protector -nostdlib -mthumb -S /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drx/drx_buf.c -o CMakeFiles/drx.dir/drx_buf.c.s

ext/drx/CMakeFiles/drx.dir/drx_buf.c.o.requires:

.PHONY : ext/drx/CMakeFiles/drx.dir/drx_buf.c.o.requires

ext/drx/CMakeFiles/drx.dir/drx_buf.c.o.provides: ext/drx/CMakeFiles/drx.dir/drx_buf.c.o.requires
	$(MAKE) -f ext/drx/CMakeFiles/drx.dir/build.make ext/drx/CMakeFiles/drx.dir/drx_buf.c.o.provides.build
.PHONY : ext/drx/CMakeFiles/drx.dir/drx_buf.c.o.provides

ext/drx/CMakeFiles/drx.dir/drx_buf.c.o.provides.build: ext/drx/CMakeFiles/drx.dir/drx_buf.c.o


# Object files for target drx
drx_OBJECTS = \
"CMakeFiles/drx.dir/drx.c.o" \
"CMakeFiles/drx.dir/drx_buf.c.o"

# External object files for target drx
drx_EXTERNAL_OBJECTS =

ext/lib32/release/libdrx.so: ext/drx/CMakeFiles/drx.dir/drx.c.o
ext/lib32/release/libdrx.so: ext/drx/CMakeFiles/drx.dir/drx_buf.c.o
ext/lib32/release/libdrx.so: ext/drx/CMakeFiles/drx.dir/build.make
ext/lib32/release/libdrx.so: ext/lib32/release/libdrcontainers.a
ext/lib32/release/libdrx.so: ext/lib32/release/libdrreg.so
ext/lib32/release/libdrx.so: ext/lib32/release/libdrmgr.so
ext/lib32/release/libdrx.so: ext/lib32/release/libdrcontainers.a
ext/lib32/release/libdrx.so: lib32/release/libdynamorio.so
ext/lib32/release/libdrx.so: ext/drx/CMakeFiles/drx.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C shared library ../lib32/release/libdrx.so"
	cd /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drx && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/drx.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
ext/drx/CMakeFiles/drx.dir/build: ext/lib32/release/libdrx.so

.PHONY : ext/drx/CMakeFiles/drx.dir/build

ext/drx/CMakeFiles/drx.dir/requires: ext/drx/CMakeFiles/drx.dir/drx.c.o.requires
ext/drx/CMakeFiles/drx.dir/requires: ext/drx/CMakeFiles/drx.dir/drx_buf.c.o.requires

.PHONY : ext/drx/CMakeFiles/drx.dir/requires

ext/drx/CMakeFiles/drx.dir/clean:
	cd /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drx && $(CMAKE_COMMAND) -P CMakeFiles/drx.dir/cmake_clean.cmake
.PHONY : ext/drx/CMakeFiles/drx.dir/clean

ext/drx/CMakeFiles/drx.dir/depend:
	cd /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio /home/ubuntu/dynamorio_bin/HOTPATCH/dynamorio/ext/drx /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drx /home/ubuntu/dynamorio_bin/HOTPATCH/build_arm/ext/drx/CMakeFiles/drx.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : ext/drx/CMakeFiles/drx.dir/depend

