RM := rm -rf
EVENTD_TARGET := eventd
EVENTD_TEST := tests/tests
EVENTDB_TEST := tests/eventdb
EVENTD_TOOL := tools/events_tool
EVENTD_PUBLISH_TOOL := tools/events_publish_tool.py
RSYSLOG-PLUGIN_TARGET := rsyslog_plugin/rsyslog_plugin
RSYSLOG-PLUGIN_TEST := rsyslog_plugin_tests/tests
EVENTD_MONIT := tools/events_monit_test.py
EVENTD_MONIT_CONF := tools/monit_events
EVENTDB_TARGET := eventdb
EVENTDB_DEFAULT_PROFILE := var/evprofile/default.json
EVENTDB_PROF := etc/eventd.json

CP := cp
MKDIR := mkdir
CC := g++
LIBS := -levent -lhiredis -lswsscommon -lpthread -lboost_thread -lboost_system -lzmq -lboost_serialization -luuid -llua5.1
TEST_LIBS := -L/usr/src/gtest -lgtest -lgtest_main -lgmock -lgmock_main

CFLAGS += -Wall -std=c++17 -fPIE -I$(PWD)/../sonic-swss-common/common
PWD := $(shell pwd)

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS) $(OBJS) $(EVENTDB_OBJS)
endif
endif

-include src/subdir.mk
-include tests/subdir.mk
-include tools/subdir.mk
-include rsyslog_plugin/subdir.mk
-include rsyslog_plugin_tests/subdir.mk

all: sonic-eventd eventd-tests eventd-tool rsyslog-plugin rsyslog-plugin-tests

sonic-eventd: $(OBJS) $(EVENTDB_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: G++ Linker'
	$(CC) $(LDFLAGS) -o $(EVENTD_TARGET) $(OBJS) $(LIBS)
	$(CC) $(LDFLAGS) -o $(EVENTDB_TARGET) $(EVENTDB_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

eventd-tool: $(TOOL_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: G++ Linker'
	$(CC) $(LDFLAGS) -o $(EVENTD_TOOL) $(TOOL_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

rsyslog-plugin: $(RSYSLOG-PLUGIN_OBJS)
	@echo 'Buidling Target: $@'
	@echo 'Invoking: G++ Linker'
	$(CC) $(LDFLAGS) -o $(RSYSLOG-PLUGIN_TARGET) $(RSYSLOG-PLUGIN_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

eventd-tests: $(TEST_OBJS) $(EVENTDB_TEST_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: G++ Linker'
	$(CC) $(LDFLAGS) -o $(EVENTD_TEST) $(TEST_OBJS) $(LIBS) $(TEST_LIBS)
	$(CC) $(LDFLAGS) -o $(EVENTDB_TEST) $(EVENTDB_TEST_OBJS) $(LIBS) $(TEST_LIBS)
	@echo 'Finished building target: $@'
	$(EVENTD_TEST)
	$(EVENTDB_TEST)
	@echo 'Finished running tests'
	@echo ' '

rsyslog-plugin-tests: $(RSYSLOG-PLUGIN-TEST_OBJS)
	@echo 'BUILDING target: $@'
	@echo 'Invoking G++ Linker'
	$(CC) $(LDFLAGS) -o $(RSYSLOG-PLUGIN_TEST) $(RSYSLOG-PLUGIN-TEST_OBJS) $(LIBS) $(TEST_LIBS)
	@echo 'Finished building target: $@'
	$(RSYSLOG-PLUGIN_TEST)
	@echo 'Finished running tests'
	@echo ' '

install:
	$(MKDIR) -p $(DESTDIR)/usr/bin
	$(MKDIR) -p $(DESTDIR)/etc/monit/conf.d
	$(MKDIR) -p $(DESTDIR)/etc/evprofile
	$(CP) $(EVENTD_TARGET) $(DESTDIR)/usr/bin
	$(CP) $(EVENTD_TOOL) $(DESTDIR)/usr/bin
	$(CP) $(EVENTD_PUBLISH_TOOL) $(DESTDIR)/usr/bin
	$(CP) $(RSYSLOG-PLUGIN_TARGET) $(DESTDIR)/usr/bin
	$(CP) $(EVENTD_MONIT) $(DESTDIR)/usr/bin
	$(CP) $(EVENTD_MONIT_CONF) $(DESTDIR)/etc/monit/conf.d
	$(CP) $(EVENTDB_TARGET) $(DESTDIR)/usr/bin
	$(CP) $(EVENTDB_PROF) $(DESTDIR)/etc/eventd.json
	$(CP) $(EVENTDB_DEFAULT_PROFILE) $(DESTDIR)/etc/evprofile/default.json

deinstall:
	$(RM) -rf $(DESTDIR)/usr
	$(RM) -rf $(DESTDIR)/etc

clean:
	-$(RM) $(EVENTD_TARGET) $(OBJS) $(EVENTD_TOOL) $(TOOL_OBJS) $(RSYSLOG-PLUGIN_TARGET) $(RSYSLOG-PLUGIN_OBJS) $(EVENTD_TEST) $(TEST_OBJS) $(RSYSLOG-PLUGIN_TEST) $(RSYSLOG-PLUGIN-TEST_OBJS)
	-@echo ' '

.PHONY: all clean dependents
