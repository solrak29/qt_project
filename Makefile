#############################################################################
# Makefile for building: qt
# Generated by qmake (3.1) (Qt 5.9.4)
# Project:  qt.pro
# Template: app
# Command: /usr/bin/i686-w64-mingw32-qmake-qt5 -o Makefile qt.pro
#############################################################################

MAKEFILE      = Makefile

first: release
install: release-install
uninstall: release-uninstall
QMAKE         = /usr/bin/i686-w64-mingw32-qmake-qt5
DEL_FILE      = rm -f
CHK_DIR_EXISTS= test -d
MKDIR         = mkdir -p
COPY          = cp -f
COPY_FILE     = cp -f
COPY_DIR      = cp -f -R
INSTALL_FILE  = install -m 644 -p
INSTALL_PROGRAM = install -m 755 -p
INSTALL_DIR   = cp -f -R
QINSTALL      = /usr/bin/i686-w64-mingw32-qmake-qt5 -install qinstall
QINSTALL_PROGRAM = /usr/bin/i686-w64-mingw32-qmake-qt5 -install qinstall -exe
DEL_FILE      = rm -f
SYMLINK       = ln -f -s
DEL_DIR       = rmdir
MOVE          = mv -f
SUBTARGETS    =  \
		release \
		debug


release: FORCE
	$(MAKE) -f $(MAKEFILE).Release
release-make_first: FORCE
	$(MAKE) -f $(MAKEFILE).Release 
release-all: FORCE
	$(MAKE) -f $(MAKEFILE).Release all
release-clean: FORCE
	$(MAKE) -f $(MAKEFILE).Release clean
release-distclean: FORCE
	$(MAKE) -f $(MAKEFILE).Release distclean
release-install: FORCE
	$(MAKE) -f $(MAKEFILE).Release install
release-uninstall: FORCE
	$(MAKE) -f $(MAKEFILE).Release uninstall
debug: FORCE
	$(MAKE) -f $(MAKEFILE).Debug
debug-make_first: FORCE
	$(MAKE) -f $(MAKEFILE).Debug 
debug-all: FORCE
	$(MAKE) -f $(MAKEFILE).Debug all
debug-clean: FORCE
	$(MAKE) -f $(MAKEFILE).Debug clean
debug-distclean: FORCE
	$(MAKE) -f $(MAKEFILE).Debug distclean
debug-install: FORCE
	$(MAKE) -f $(MAKEFILE).Debug install
debug-uninstall: FORCE
	$(MAKE) -f $(MAKEFILE).Debug uninstall

Makefile: qt.pro /usr/lib/qt5/i686-w64-mingw32/mkspecs/win32-g++/qmake.conf /usr/lib/qt5/i686-w64-mingw32/mkspecs/features/spec_pre.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/qdevice.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/device_config.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/common/sanitize.conf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/common/gcc-base.conf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/common/g++-base.conf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/common/angle.conf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/qconfig.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_accessibility_support_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_bootstrap_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_concurrent.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_concurrent_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_core.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_core_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_dbus.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_dbus_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_devicediscovery_support_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_eventdispatcher_support_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_fb_support_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_fontdatabase_support_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_gui.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_gui_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_network.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_network_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_opengl.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_opengl_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_openglextensions.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_openglextensions_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_platformcompositor_support_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_printsupport.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_printsupport_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_sql.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_sql_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_testlib.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_testlib_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_theme_support_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_widgets.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_widgets_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_xml.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_xml_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_zlib_private.pri \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/qt_functions.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/qt_config.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/win32-g++/qmake.conf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/spec_post.prf \
		.qmake.stash \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/exclusive_builds.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/toolchain.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/default_pre.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/win32/default_pre.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/resolve_config.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/exclusive_builds_post.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/default_post.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/precompile_header.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/warn_on.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/qt.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/resources.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/moc.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/win32/opengl.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/uic.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/qmake_use.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/file_copies.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/win32/windows.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/testcase_targets.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/exceptions.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/yacc.prf \
		/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/lex.prf \
		qt.pro \
		/usr/i686-w64-mingw32/sys-root/mingw/lib/Qt5Widgets.prl \
		/usr/i686-w64-mingw32/sys-root/mingw/lib/Qt5Gui.prl \
		/usr/i686-w64-mingw32/sys-root/mingw/lib/Qt5Core.prl
	$(QMAKE) -o Makefile qt.pro
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/spec_pre.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/qdevice.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/device_config.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/common/sanitize.conf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/common/gcc-base.conf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/common/g++-base.conf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/common/angle.conf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/qconfig.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_accessibility_support_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_bootstrap_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_concurrent.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_concurrent_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_core.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_core_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_dbus.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_dbus_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_devicediscovery_support_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_eventdispatcher_support_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_fb_support_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_fontdatabase_support_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_gui.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_gui_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_network.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_network_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_opengl.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_opengl_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_openglextensions.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_openglextensions_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_platformcompositor_support_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_printsupport.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_printsupport_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_sql.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_sql_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_testlib.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_testlib_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_theme_support_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_widgets.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_widgets_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_xml.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_xml_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/modules/qt_lib_zlib_private.pri:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/qt_functions.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/qt_config.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/win32-g++/qmake.conf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/spec_post.prf:
.qmake.stash:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/exclusive_builds.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/toolchain.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/default_pre.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/win32/default_pre.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/resolve_config.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/exclusive_builds_post.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/default_post.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/precompile_header.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/warn_on.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/qt.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/resources.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/moc.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/win32/opengl.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/uic.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/qmake_use.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/file_copies.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/win32/windows.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/testcase_targets.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/exceptions.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/yacc.prf:
/usr/lib/qt5/i686-w64-mingw32/mkspecs/features/lex.prf:
qt.pro:
/usr/i686-w64-mingw32/sys-root/mingw/lib/Qt5Widgets.prl:
/usr/i686-w64-mingw32/sys-root/mingw/lib/Qt5Gui.prl:
/usr/i686-w64-mingw32/sys-root/mingw/lib/Qt5Core.prl:
qmake: FORCE
	@$(QMAKE) -o Makefile qt.pro

qmake_all: FORCE

make_first: release-make_first debug-make_first  FORCE
all: release-all debug-all  FORCE
clean: release-clean debug-clean  FORCE
distclean: release-distclean debug-distclean  FORCE
	-$(DEL_FILE) Makefile
	-$(DEL_FILE) .qmake.stash

release-mocclean:
	$(MAKE) -f $(MAKEFILE).Release mocclean
debug-mocclean:
	$(MAKE) -f $(MAKEFILE).Debug mocclean
mocclean: release-mocclean debug-mocclean

release-mocables:
	$(MAKE) -f $(MAKEFILE).Release mocables
debug-mocables:
	$(MAKE) -f $(MAKEFILE).Debug mocables
mocables: release-mocables debug-mocables

check: first

benchmark: first
FORCE:

$(MAKEFILE).Release: Makefile
$(MAKEFILE).Debug: Makefile
