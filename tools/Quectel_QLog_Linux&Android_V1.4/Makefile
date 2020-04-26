SOURCES =  main.c asr.c mdm.c tty2tcp.c sahara.c tftp.c ymodem.c

ifeq ($(CC),cc)
CC=${CROSS_COMPILE}gcc
endif

CFLAGS+=-Wno-format-overflow

linux: clean
	${CC} -Wall -g $(CFLAGS) $(SOURCES) -o QLog -lpthread -ldl

clean:
	rm -rf QLog *.exe *.dSYM *.obj *.exp .*o *.lib *~ libs out

export USE_NDK=1
NDK_BUILD=/workspace/android-ndk/android-ndk-r10e/ndk-build
#NDK_BUILD=ndk-build
NDK_PROJECT_PATH=`pwd`
NDK_DEBUG=0
APP_ABI=armeabi,arm64-v8a#,x86,mips,armeabi-v7a,arm64-v8a,mips64,x86_64
APP_PLATFORM=android-14 #8~2.2 9~2.3 14~4.0 17~4.2 19~4.4 21~5.0 22~5.1 23~6.0 24~6.x
APP_BUILD_SCRIPT=Android.mk
NDK_APPLICATION_MK=Application.mk
NDK_OUT=out

android: clean
	$(NDK_BUILD) V=0 NDK_OUT=$(NDK_OUT)  NDK_LIBS_OUT=$(NDK_LIBS_OUT) APP_BUILD_SCRIPT=$(APP_BUILD_SCRIPT) NDK_PROJECT_PATH=$(NDK_PROJECT_PATH) NDK_DEBUG=$(NDK_DEBUG) APP_ABI=$(APP_ABI) APP_PLATFORM=$(APP_PLATFORM)
	#$(NDK_BUILD) V=0 NDK_OUT=$(NDK_OUT)  NDK_APPLICATION_MK=$(NDK_APPLICATION_MK) NDK_LIBS_OUT=$(NDK_LIBS_OUT) APP_BUILD_SCRIPT=$(APP_BUILD_SCRIPT) NDK_PROJECT_PATH=$(NDK_PROJECT_PATH) NDK_DEBUG=$(NDK_DEBUG) APP_ABI=$(APP_ABI) APP_PLATFORM=$(APP_PLATFORM)
