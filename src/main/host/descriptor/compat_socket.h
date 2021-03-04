/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */

#ifndef SRC_MAIN_HOST_DESCRIPTOR_COMPAT_SOCKET_H_
#define SRC_MAIN_HOST_DESCRIPTOR_COMPAT_SOCKET_H_

#include "main/bindings/c/bindings.h"
#include "main/host/descriptor/socket.h"
#include "main/utility/tagged_ptr.h"

typedef enum _CompatSocketTypes CompatSocketTypes;
enum _CompatSocketTypes {
    CST_LEGACY_SOCKET,
    CST_SOCKET_FILE,
};

typedef union _CompatSocketObject CompatSocketObject;
union _CompatSocketObject {
    Socket* as_legacy_socket;
    const SocketFile* as_socket_file;
};

typedef struct _CompatSocket CompatSocket;
struct _CompatSocket {
    CompatSocketTypes type;
    CompatSocketObject object;
};

/* reference counting */
CompatSocket compatsocket_cloneRef(CompatSocket* socket);
void compatsocket_drop(CompatSocket* socket);

/* converting between a CompatSocket and a tagged pointer */
uintptr_t compatsocket_toTagged(const CompatSocket* socket);
CompatSocket compatsocket_fromTagged(uintptr_t ptr);

/* compatability wrappers */
ProtocolType compatsocket_getProtocol(CompatSocket* socket);
bool compatsocket_getPeerName(CompatSocket* socket, in_addr_t* ip, in_port_t* port);
bool compatsocket_getSocketName(CompatSocket* socket, in_addr_t* ip, in_port_t* port);
const Packet* compatsocket_peekNextOutPacket(CompatSocket* socket);
void compatsocket_pushInPacket(CompatSocket* socket, Packet* packet);
Packet* compatsocket_pullOutPacket(CompatSocket* socket);

#endif /* SRC_MAIN_HOST_DESCRIPTOR_COMPAT_SOCKET_H_ */
