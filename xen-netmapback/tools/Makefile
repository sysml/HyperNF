PROGS	=	xennet_ctrl

CLEANFILES = $(PROGS) *.o
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wextra

all: $(PROGS)

xennet_ctrl:
	$(CC) $(CFLAGS) -o xennet_ctrl xennet_ctrl.c $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)

