//#define DEBUGGING

#include "global.h"
#include "WebSocketClient.h"

#include "sha1.h"
#include "base64.h"


bool WebSocketClient::handshake(Client &client, bool socketio, const char * additionalHeaders) {

    additionalHeaders = additionalHeaders
    socket_client = &client;
    issocketio = socketio;
    strcpy(sid, "");

    // If there is a connected client->
    if (socket_client->connected()) {
        // Check request and look for websocket handshake
#ifdef DEBUGGING
            Serial.println(F("Client connected"));
#endif
        if (issocketio && strlen(sid) == 0) {
            analyzeRequest();
        }

        if (analyzeRequest()) {
#ifdef DEBUGGING
                Serial.println(F("Websocket established"));
#endif

                return true;

        } else {
            // Might just need to break until out of socket_client loop.
#ifdef DEBUGGING
            Serial.println(F("Invalid handshake"));
#endif
            disconnectStream();

            return false;
        }
    } else {
        return false;
    }
}

bool WebSocketClient::analyzeRequest() {
    String temp;

    int bite;
    bool foundupgrade = false;
    bool foundsid = false;
    unsigned long intkey[2];
    String serverKey;
    char keyStart[17];
    char b64Key[25];
    String key = "------------------------";

    if (!issocketio || (issocketio && strlen(sid) > 0)) {

#ifdef DEBUGGING
    Serial.println(F("Sending websocket upgrade headers"));
#endif

        randomSeed(analogRead(0));

        for (int i=0; i<16; ++i) {
            keyStart[i] = (char)random(1, 256);
        }

        base64_encode(b64Key, keyStart, 16);

        for (int i=0; i<24; ++i) {
            key[i] = b64Key[i];
        }

        socket_client->print(F("GET "));
        socket_client->print(path);
        if (issocketio) {
            socket_client->print(F("socket.io/?EIO=3&transport=websocket&sid="));
            socket_client->print(sid);
        }
        socket_client->print(F(" HTTP/1.1\r\n"));
        socket_client->print(F("Upgrade: websocket\r\n"));
        socket_client->print(F("Connection: Upgrade\r\n"));
        socket_client->print(F("Sec-WebSocket-Key: "));
        socket_client->print(key);
        socket_client->print(CRLF);
        socket_client->print(F("Sec-WebSocket-Protocol: "));
        socket_client->print(protocol);
        socket_client->print(CRLF);
        socket_client->print(F("Sec-WebSocket-Version: 13\r\n"));

    } else {

#ifdef DEBUGGING
    Serial.println(F("Sending socket.io session request headers"));
#endif

        socket_client->print(F("GET "));
        socket_client->print(path);
        socket_client->print(F("socket.io/?EIO=3&transport=polling HTTP/1.1\r\n"));
        socket_client->print(F("Connection: keep-alive\r\n"));
    }

    socket_client->print(F("Host: "));
    socket_client->print(host);
    if(_additionalHeaders != nullptr){
        socket_client->print(_additionalHeaders);
    }

    socket_client->print(CRLF);
    socket_client->print(CRLF);

#ifdef DEBUGGING
    Serial.println(F("Analyzing response headers"));
#endif

    while (socket_client->connected() && !socket_client->available()) {
        delay(100);
        Serial.println("Waiting...");
    }

    // TODO: More robust string extraction
    while ((bite = socket_client->read()) != -1) {

        temp += (char)bite;

        if ((char)bite == '\n') {
#ifdef DEBUGGING
            Serial.print("Got Header: " + temp);
#endif
            if (!foundupgrade && temp.startsWith("Upgrade: websocket")) {
                foundupgrade = true;
            } else if (temp.startsWith("Sec-WebSocket-Accept: ")) {
                serverKey = temp.substring(22,temp.length() - 2); // Don't save last CR+LF
            } else if (!foundsid && temp.startsWith("Set-Cookie: ")) {
                foundsid = true;
                String tempsid = temp.substring(temp.indexOf("=") + 1, temp.length() - 2); // Don't save last CR+LF
                strcpy(sid, tempsid.c_str());
            }
            temp = "";
        }

        if (!socket_client->available()) {
          delay(20);
        }
    }

    if (issocketio && foundsid && !foundupgrade) {
        return true;
    }

    key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t *hash;
    char result[21];
    char b64Result[30];

    Sha1.init();
    Sha1.print(key);
    hash = Sha1.result();

    for (int i=0; i<20; ++i) {
        result[i] = (char)hash[i];
    }
    result[20] = '\0';

    base64_encode(b64Result, result, 20);

    // if the keys match, good to go
    return serverKey.equals(String(b64Result));
}


bool WebSocketClient::handleStream(String& data, uint8_t *opcode) {
    uint8_t msgtype;
    uint8_t bite;
    unsigned int length;
    uint8_t mask[4];
    uint8_t index;
    unsigned int i;
    bool hasMask = false;

    if (!socket_client->connected() || !socket_client->available())
    {
        return false;
    }

    msgtype = timedRead();
    if (!socket_client->connected()) {
        return false;
    }

    length = timedRead();

    if (length & WS_MASK) {
        hasMask = true;
        length = length & ~WS_MASK;
    }


    if (!socket_client->connected()) {
        return false;
    }

    index = 6;

    if (length == WS_SIZE16) {
        length = timedRead() << 8;
        if (!socket_client->connected()) {
            return false;
        }

        length |= timedRead();
        if (!socket_client->connected()) {
            return false;
        }

    } else if (length == WS_SIZE64) {
#ifdef DEBUGGING
        Serial.println(F("No support for over 16 bit sized messages"));
#endif
        return false;
    }

    if (hasMask) {
        // get the mask
        mask[0] = timedRead();
        if (!socket_client->connected()) {
            return false;
        }

        mask[1] = timedRead();
        if (!socket_client->connected()) {

            return false;
        }

        mask[2] = timedRead();
        if (!socket_client->connected()) {
            return false;
        }

        mask[3] = timedRead();
        if (!socket_client->connected()) {
            return false;
        }
    }

    data = "";

    if (opcode != NULL)
    {
      *opcode = msgtype & ~WS_FIN;
    }

    if (hasMask) {
        for (i=0; i<length; ++i) {
            data += (char) (timedRead() ^ mask[i % 4]);
            if (!socket_client->connected()) {
                return false;
            }
        }
    } else {
        for (i=0; i<length; ++i) {
            data += (char) timedRead();
            if (!socket_client->connected()) {
                return false;
            }
        }
    }

    return true;
}

bool readByte(uint8_t * byte){
    return socket_client->read(byte, 1) == 1;
}

bool readShort(uint8_t * out){
    uint8_t buf[2];
    if(socket_client->read(buf, 2) != 2){
        return false;
    }

    out[0] = (buf[1] << 8) | (buf[0]);
    return true;
}


//   | --- byte 1 -- | --- byte 2 -- | --- byte 3 -- | --- byte 4 -- |    
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-------+-+-------------+-------------------------------+
//   |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//   |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//   |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//   | |1|2|3|       |K|             |                               |
//   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//   |     Extended payload length continued, if payload len == 127  |
//   + - - - - - - - - - - - - - - - +-------------------------------+
//   |                               |Masking-key, if MASK set to 1  |
//   +-------------------------------+-------------------------------+
//   | Masking-key (continued)       |          Payload Data         |
//   +-------------------------------- - - - - - - - - - - - - - - - +
//   :                     Payload Data continued ...                :
//   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//   |                     Payload Data continued ...                |
//   +---------------------------------------------------------------+

bool WebSocketClient::handleStream(uint8_t *data, size_t data_size, uint8_t *opcode) {
    uint8_t bite;
    unsigned int length;
    uint8_t mask[4];
    bool hasMask = false;


    uint8_t headers[2]
    if(!socket_client->connected() || !socket_client->available() || socket_client->read(headers, 2) != 2){
        return false;
    }

    const uint16_t length = headers[1] & ~WS_MASK;
    const bool hasMask = headers[1] & WS_MASK == WS_MASK;
    if (opcode != NULL)
    {
      *opcode = headers[0] & 0x0F;
    }


    // if length == 126, the message length is actually stored in the
    // the following 2 bytes. 
    if (length == WS_SIZE16) {
       if(!readShort(&length)){
        return false;
       }

    } else if (length == WS_SIZE64) {
#ifdef DEBUGGING
        Serial.println(F("No support for over 16 bit sized messages"));
#endif
        return false;
    }

    if (hasMask) {
        // get the mask
        if(socket_client->read(mask, 4) != 4){
            return false;
        }
    }


    if(length > data_size){
        Log.errorln("Got websocket message of length %i, but data size is only %i", length, data_size);
        return false;
    }
    if (socket_client->read(data, length) != length)
    {
        return false;
    }

    if (hasMask) {
        for (i = 0; i < length; ++i) {
            data[i] = data[i] ^ mask[i % 4];
        }
    }

    return true;
}

void WebSocketClient::disconnectStream() {
#ifdef DEBUGGING
    Serial.println(F("Terminating socket"));
#endif
    // Should send 0x8700 to server to tell it I'm quitting here.
    socket_client->write((uint8_t) 0x87);
    socket_client->write((uint8_t) 0x00);

    socket_client->flush();
    delay(10);
    socket_client->stop();
    strcpy(sid, "");
}

bool WebSocketClient::getData(String& data, uint8_t *opcode) {
    return handleStream(data, opcode);
}

int WebSocketClient::getData(uint8_t *data, size_t data_size, uint8_t *opcode) {
    return handleStream(data, data_size, opcode);
}

void WebSocketClient::sendData(const char *str, uint8_t opcode, bool fast) {
#ifdef DEBUGGING
    Serial.print(F("Sending data: "));
    Serial.println(str);
#endif
    if (socket_client->connected()) {
        if (fast) {
            sendEncodedDataFast(str, opcode);
        } else {
            sendEncodedData(str, opcode);
        }
    }
}

void WebSocketClient::sendData(String str, uint8_t opcode, bool fast) {
#ifdef DEBUGGING
    Serial.print(F("Sending data: "));
    Serial.println(str);
#endif
    if (socket_client->connected()) {
        if (fast) {
            sendEncodedDataFast(str, opcode);
        } else {
            sendEncodedData(str, opcode);
        }
    }
}

int WebSocketClient::timedRead()
{
    yield();
    for (int i = 0; i < 5000 && !socket_client->available(); ++i)
    {
        delay(1);
    }
    return socket_client->read();
}

void WebSocketClient::sendEncodedData(char *str, uint8_t opcode) {
    uint8_t mask[4];
    int size = strlen(str);

    // Opcode; final fragment
    socket_client->write(opcode | WS_FIN);

    // NOTE: no support for > 16-bit sized messages
    if (size > 125) {
        socket_client->write(WS_SIZE16 | WS_MASK);
        socket_client->write((uint8_t) (size >> 8));
        socket_client->write((uint8_t) (size & 0xFF));
    } else {
        socket_client->write((uint8_t) size | WS_MASK);
    }

    if (WS_MASK > 0) {
        //Serial.println("MASK");
        mask[0] = random(0, 256);
        mask[1] = random(0, 256);
        mask[2] = random(0, 256);
        mask[3] = random(0, 256);

        socket_client->write(mask[0]);
        socket_client->write(mask[1]);
        socket_client->write(mask[2]);
        socket_client->write(mask[3]);
    }

    for (int i=0; i<size; ++i) {
        if (WS_MASK > 0) {
            //Serial.println("send with MASK");
            //delay(20);
            socket_client->write(str[i] ^ mask[i % 4]);
        } else {
            socket_client->write(str[i]);
        }
    }
}

void WebSocketClient::sendEncodedDataFast(char *str, uint8_t opcode) {
    uint8_t mask[4];
    int size = strlen(str);
    int size_buf = size + 1;
    if (size > 125) {
        size_buf += 3;
    } else {
        size_buf += 1;
    }
    if (WS_MASK > 0) {
        size_buf += 4;
    }

    char buf[size_buf];
    char tmp[2];

    // Opcode; final fragment
    sprintf(tmp, "%c", (char)(opcode | WS_FIN));
    strcpy(buf, tmp);

    // NOTE: no support for > 16-bit sized messages
    if (size > 125) {
        sprintf(tmp, "%c", (char)(WS_SIZE16 | WS_MASK));
        strcat(buf, tmp);
        sprintf(tmp, "%c", (char) (size >> 8));
        strcat(buf, tmp);
        sprintf(tmp, "%c", (char) (size & 0xFF));
        strcat(buf, tmp);
    } else {
        sprintf(tmp, "%c", (char) size | WS_MASK);
        strcat(buf, tmp);
    }

    if (WS_MASK > 0) {
        mask[0] = random(0, 256);
        mask[1] = random(0, 256);
        mask[2] = random(0, 256);
        mask[3] = random(0, 256);

        sprintf(tmp, "%c", (char) mask[0]);
        strcat(buf, tmp);
        sprintf(tmp, "%c", (char) mask[1]);
        strcat(buf, tmp);
        sprintf(tmp, "%c", (char) mask[2]);
        strcat(buf, tmp);
        sprintf(tmp, "%c", (char) mask[3]);
        strcat(buf, tmp);

        for (int i=0; i<size; ++i) {
            str[i] = str[i] ^ mask[i % 4];
        }
    }

    strcat(buf, str);
    socket_client->write((uint8_t*)buf, size_buf);
}


void WebSocketClient::sendData(const uint8_t  *data, constsize_t size, uint8_t opcode) {
    int size_buf = size + 2;

    if (size > 125) {
        size_buf += 2;
    } 

    if (WS_MASK > 0) {
        size_buf += 4;
    }

    uint8_t buf[size_buf];

    bufPtr = 0;
    // Opcode; final fragment
    buf[bufPtr++] = opcode | WS_FIN;

    // NOTE: no support for > 16-bit sized messages
    if (size > 125) {
        buf[bufPtr++] = WS_SIZE16 | WS_MASK;
        buf[bufPtr++] = size >> 8;
        buf[bufPtr++] = size & 0xFF;
    } else {
        buf[bufPtr++] = size | WS_MASK;
    }

    if (WS_MASK > 0) {
       uint8_t mask[4];
       for (int i = 0; i < 4; +i) {
            mask[i] = random(0, 256);
            buf[bufPtr++] = mask[i];
        }

        for (int i = 0; i < size; ++i) {
            buf[bufPtr++] = str[i] ^ mask[i % 4];
        }
    } else {
        // Should never happen on client.
        memcpy(buf[bufPtr], data, size);
    }

    socket_client->write(buf, size_buf);
}

void WebSocketClient::sendEncodedData(String str, uint8_t opcode) {
    int size = str.length() + 1;
    char cstr[size];

    str.toCharArray(cstr, size);

    sendEncodedData(cstr, opcode);
}


void WebSocketClient::sendEncodedDataFast(String str, uint8_t opcode) {
    int size = str.length() + 1;
    char cstr[size];

    str.toCharArray(cstr, size);

    sendEncodedDataFast(cstr, opcode);
}
