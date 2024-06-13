include ../../rules/sonic-nettools.mk

$(addprefix $(DEST)/, $(SONIC_NETTOOLS)): $(DEST)/% :
	$(CXX) -o wol src/wol.cpp 
