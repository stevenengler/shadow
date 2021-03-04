/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */

#ifndef SRC_MAIN_HOST_DESCRIPTOR_COMPAT_SOCKET_H_
#define SRC_MAIN_HOST_DESCRIPTOR_COMPAT_SOCKET_H_

typedef enum _CompatSocketTypes CompatSocketTypes;
typedef union _CompatSocketObject CompatSocketObject;
typedef struct _CompatSocket CompatSocket;

#include "main/bindings/c/bindings-opaque.h"
#include "main/host/descriptor/socket.h"
#include "main/utility/tagged_ptr.h"

enum _CompatSocketTypes {
    CST_LEGACY_SOCKET,
    CST_SOCKET_FILE,
};

union _CompatSocketObject {
    Socket* as_legacy_socket;
    const SocketFile* as_socket_file;
};

struct _CompatSocket {
    CompatSocketTypes type;
    CompatSocketObject object;
};

CompatSocket compatsocket_fromLegacySocket(Socket* socket);
CompatSocket compatsocket_fromSocketFile(const SocketFile* socket);

/* reference counting */
CompatSocket compatsocket_cloneRef(const CompatSocket* socket);
void compatsocket_drop(const CompatSocket* socket);

/* converting between a CompatSocket and a tagged pointer */
uintptr_t compatsocket_toTagged(const CompatSocket* socket);
CompatSocket compatsocket_fromTagged(uintptr_t ptr);

/* compatability wrappers */
ProtocolType compatsocket_getProtocol(const CompatSocket* socket);
bool compatsocket_getPeerName(const CompatSocket* socket, in_addr_t* ip, in_port_t* port);
bool compatsocket_getSocketName(const CompatSocket* socket, in_addr_t* ip, in_port_t* port);
const Packet* compatsocket_peekNextOutPacket(const CompatSocket* socket);
void compatsocket_pushInPacket(const CompatSocket* socket, Packet* packet);
Packet* compatsocket_pullOutPacket(const CompatSocket* socket);

#endif /* SRC_MAIN_HOST_DESCRIPTOR_COMPAT_SOCKET_H_ */
