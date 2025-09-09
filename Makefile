.PHONY: all clean ns js as

all: ns js as

ns:
	$(MAKE) -C NetworkServer

js:
	$(MAKE) -C JoinServer

as:
	$(MAKE) -C AppServer

clean:
	$(MAKE) -C NetworkServer clean
	$(MAKE) -C JoinServer clean
	$(MAKE) -C AppServer clean
