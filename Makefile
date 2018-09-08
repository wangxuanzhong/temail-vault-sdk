all: compile_java compile_cpp

SHARED_OPTION=-shared
CC_LIB=-L./lib -ltsb -lssl -lcrypto -luuid -lstdc++
LIB_PATH=${LD_LIBRARY_PATH}

compile_cpp:
	g++ $(SHARED_OPTION) -fPIC -std=c++0x \
		-I${JAVA_HOME}/include \
		-I${JAVA_HOME}/include/linux \
		cpp/TSBJni.cpp $(CC_LIB) \
		-o libTSBJni.so

compile_java:
	$(JAVA_HOME)/bin/javac -h cpp -d target src/main/java/com/temail/tsb/TSBSdk.java src/main/java/com/syswin/temail/vault/sdk/VaultSdk.java

test:
	export LD_LIBRARY_PATH=${LIB_PATH}:$(CURDIR)/lib
	$(JAVA_HOME)/bin/java -Djava.library.path="$(CURDIR)/lib:$(CURDIR)/" -cp target com.syswin.temail.vault.sdk.VaultSdk

clean:
	-rm -rfv target/*
	-rm cpp/com_temail_tsb_TSBSdk.h
	-rm -f lib/libTSBJni.so
