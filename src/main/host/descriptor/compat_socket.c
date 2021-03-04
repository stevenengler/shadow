#include "main/host/descriptor/compat_socket.h"

#include "main/bindings/c/bindings.h"
#include "main/host/descriptor/socket.h"
#include "main/utility/tagged_ptr.h"
#include "support/logger/logger.h"

CompatSocket compatsocket_cloneRef(CompatSocket* socket) {
    CompatSocket new_socket = {
        .type = socket->type,
        .object = socket->object,
    };

    if (new_socket.type == CST_LEGACY_SOCKET) {
        descriptor_ref(new_socket.object.as_legacy_socket);
    } else if (new_socket.type == CST_SOCKET_FILE) {
        new_socket.object.as_socket_file = socketfile_cloneRef(new_socket.object.as_socket_file);
    } else {
        error("Unexpected CompatSocket type");
    }

    return new_socket;
}

void compatsocket_drop(CompatSocket* socket) {
    if (socket->type == CST_LEGACY_SOCKET) {
        descriptor_unref(socket->object.as_legacy_socket);
    } else if (socket->type == CST_SOCKET_FILE) {
        socketfile_drop(socket->object.as_socket_file);
    } else {
        error("Unexpected CompatSocket type");
    }
}

uintptr_t compatsocket_toTagged(const CompatSocket* socket) {
    CompatSocketTypes type = socket->type;
    CompatSocketObject object = socket->object;

	const void* object_ptr;

    if (socket->type == CST_LEGACY_SOCKET) {
        object_ptr = object.as_legacy_socket;
    } else if (socket->type == CST_SOCKET_FILE) {
        object_ptr = object.as_socket_file;
    } else {
        error("Unexpected CompatSocket type");
    }

    return tagPtr(object_ptr, type);
}

CompatSocket compatsocket_fromTagged(uintptr_t ptr) {
    CompatSocketTypes type;
    CompatSocketObject object;

    uintptr_t tag = 0;
    void* object_ptr = untagPtr(ptr, &tag);

    if (tag == CST_LEGACY_SOCKET) {
        object.as_legacy_socket = object_ptr;
    } else if (tag == CST_SOCKET_FILE) {
        object.as_socket_file = object_ptr;
    } else {
        error("Unexpected socket pointer tag");
    }

	type = tag;

    CompatSocket socket = {
        .type = type,
        .object = object,
    };

    return socket;
}

ProtocolType compatsocket_getProtocol(CompatSocket* socket) {
    if (socket->type == CST_LEGACY_SOCKET) {
        return socket_getProtocol(socket->object.as_legacy_socket);
    } else if (socket->type == CST_SOCKET_FILE) {
        return socketfile_getProtocol(socket->object.as_socket_file);
    } else {
        error("Unexpected CompatSocket type");
    }
}

bool compatsocket_getPeerName(CompatSocket* socket, in_addr_t* ip, in_port_t* port) {
    if (socket->type == CST_LEGACY_SOCKET) {
        return socket_getPeerName(socket->object.as_legacy_socket, ip, port);
    } else if (socket->type == CST_SOCKET_FILE) {
        return socketfile_getPeerName(socket->object.as_socket_file, ip, port);
    } else {
        error("Unexpected CompatSocket type");
    }
}

bool compatsocket_getSocketName(CompatSocket* socket, in_addr_t* ip, in_port_t* port) {
    if (socket->type == CST_LEGACY_SOCKET) {
        return socket_getSocketName(socket->object.as_legacy_socket, ip, port);
    } else if (socket->type == CST_SOCKET_FILE) {
        return socketfile_getSocketName(socket->object.as_socket_file, ip, port);
    } else {
        error("Unexpected CompatSocket type");
    }
}

const Packet* compatsocket_peekNextOutPacket(CompatSocket* socket) {
    if (socket->type == CST_LEGACY_SOCKET) {
        return socket_peekNextOutPacket(socket->object.as_legacy_socket);
    } else if (socket->type == CST_SOCKET_FILE) {
        return socketfile_peekNextOutPacket(socket->object.as_socket_file);
    } else {
        error("Unexpected CompatSocket type");
    }
}

void compatsocket_pushInPacket(CompatSocket* socket, Packet* packet) {
    if (socket->type == CST_LEGACY_SOCKET) {
        socket_pushInPacket(socket->object.as_legacy_socket, packet);
    } else if (socket->type == CST_SOCKET_FILE) {
        socketfile_pushInPacket(socket->object.as_socket_file, packet);
    } else {
        error("Unexpected CompatSocket type");
    }
}

Packet* compatsocket_pullOutPacket(CompatSocket* socket) {
    if (socket->type == CST_LEGACY_SOCKET) {
        return socket_pullOutPacket(socket->object.as_legacy_socket);
    } else if (socket->type == CST_SOCKET_FILE) {
        return socketfile_pullOutPacket(socket->object.as_socket_file);
    } else {
        error("Unexpected CompatSocket type");
    }
}
