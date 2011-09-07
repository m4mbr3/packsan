******************************************************************
**	Packsan - packet sanitizer for Linux kernel		**
******************************************************************

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

PACKSAN PROJECT GOAL
The goal of Packsan project is finding strings inside UDP and TCP segments and substitute them with selected ones. Due to TCP synchronization mechanism, it is possible to replace only strings with the same length as the original ones (otherwise there is packet loss and connection lock). A variable length substitution is instead available with UDP, but putting a much more long string is not suggested because of kernel pagination troubles (and possible kernel panics: be careful!).
The iptables rules must be inserted in the mangle table of INPUT or POSTROUTING hooks; other places are not allowed.

DIRECTORIES STRUCTURE AND MODULE BUILDING
Directories are named by the module sources they contain: thus Matcher contains the matcher module sources, Target the target sources and the directories which begin with shared_lib_ contain the sources of libraries to be copied into the proper kernel folder, in order to interface the modules with the userspace.
Every directory contains a Makefile with the basic rules to build the module and perform the cleanup: "make clean" removes all the compiled files, and in Matcher and Target the "make" command builds the proper module (xt_packsan.ko for the matcher, xt_PACKSAN.ko for the target); in shared_lib_* dirs it is necessary to specify the name of the file to build, since different Linux distros have different conventions. Thus in Slackware 13.37 the matcher lib module must be named libipt_packsan.so and must be inserted into /usr/libexec/xtables/, while in OpenSUSE the name must be libxt_packsan.so and the directory must be /usr/lib/xtables. Check your distro!
Finally it is necessary to load x_tables via the command "modprobe x_tables" and the built modules via "insmod xt_packsan.ko" and "insmod xt_PACKSAN.ko", and configure Iptables via the commands

iptables -A (INPUT|POSTROUTING) -t mangle -m packsan -j PACKSAN

A VERY VERBOSE logging activity is by default enabled, and can be seen with dmesg; to disable it the LOG macro inside both modules must be set to 0.
Default searched strings are "carne" and "gelato" (we were hungry at the time we wrote them ...).

Comments, critics and suggestions are well appreciated and can be sent to packsanteam@gmail.com
