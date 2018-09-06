all: compile_java compile_cpp

SHARED_OPTION=-shared
CC_LIB=-L./lib -ltsb -lstdc++
LIB_PATH=${LD_LIBRARY_PATH}

compile_cpp:
	g++ $(SHARED_OPTION) -fPIC -std=c++0x \
		-I${JAVA_HOME}/include \
		-I${JAVA_HOME}/include/linux \
		cpp/com_syswin_temail_vault_sdk_VaultSdk.cpp $(CC_LIB) \
		-o libVaultSdk.so

compile_java:
  mkdir target
	$(JAVA_HOME)/bin/javac -h cpp -d target src/main/java/com/syswin/temail/vault/sdk/VaultSdk.java

test:
	export LD_LIBRARY_PATH=${LIB_PATH}:$(CURDIR)/lib
	$(JAVA_HOME)/bin/java -Djava.library.path="$(CURDIR)/lib:$(CURDIR)/" -cp target com.syswin.temail.vault.sdk.VaultSdk

clean:
	-rm -rfv target/*
	-rm cpp/com_syswin_temail_vault_sdk_VaultSdk.h
	-rm -f lib/libVaultSdk.so
