include ../../rules/sonic-nettools.mk

$(addprefix $(DEST)/, $(SONIC_NETTOOLS)): $(DEST)/% :
	rm wol
	$(CXX) -o wol src/wol.cpp 
