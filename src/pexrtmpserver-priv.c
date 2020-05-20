#include "pexrtmpserver-types.h"

const gchar *
pex_rtmp_server_status_name (PexRtmpServerStatus status)
{
  switch (status) {
    case PEX_RTMP_SERVER_STATUS_OK:
      return "OK";
      break;
    case PEX_RTMP_SERVER_STATUS_BAD:
      return "BAD";
      break;
    case PEX_RTMP_SERVER_STATUS_FD_ERROR:
      return "FD_ERROR";
      break;
    case PEX_RTMP_SERVER_STATUS_SEND_FAILED:
      return "SEND_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_RECV_EOF:
      return "RECV_EOF";
      break;
    case PEX_RTMP_SERVER_STATUS_RECV_FAILED:
      return "RECV_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_SSL_NEW_FAILED:
      return "SSL_NEW_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_SSL_WRITE_FAILED:
      return "SSL_WRITE_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_SSL_READ_FAILED:
      return "SSL_READ_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_SSL_ACCEPT_FAILED:
      return "SSL_ACCEPT_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_TCP_HANDSHAKE_FAILED:
      return "TCP_HANDSHAKE_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_INVALID_MSG_LEN:
      return "INVALID_MSG_LEN";
      break;
    case PEX_RTMP_SERVER_STATUS_MULTIPLE_PUBLISHERS:
      return "MULTIPLE_PUBLISHERS";
      break;
    case PEX_RTMP_SERVER_STATUS_ERROR:
      return "ERROR";
      break;
    case PEX_RTMP_SERVER_STATUS_AUTH_REJECTED:
      return "AUTH_REJECTED";
      break;
    case PEX_RTMP_SERVER_STATUS_NEED_AUTH:
      return "NEED_AUTH";
      break;
    case PEX_RTMP_SERVER_STATUS_INVALID_FCPUBLISH:
      return "INVALID_FCPUBLISH";
      break;
    case PEX_RTMP_SERVER_STATUS_INVALID_PUBLISH:
      return "INVALID_PUBLISH";
      break;
    case PEX_RTMP_SERVER_STATUS_PUBLISH_REJECTED:
      return "PUBLISH_REJECTED";
      break;
    case PEX_RTMP_SERVER_STATUS_PLAY_REJECTED:
      return "PLAY_REJECTED";
      break;
    case PEX_RTMP_SERVER_STATUS_INVALID_PLAY:
      return "INVALID_PLAY";
      break;
    case PEX_RTMP_SERVER_STATUS_INVALID_PLAY2:
      return "INVALID_PLAY2";
      break;
    case PEX_RTMP_SERVER_STATUS_INVALID_INVOKE:
      return "INVALID_INVOKE";
      break;
    case PEX_RTMP_SERVER_STATUS_INVALID_MSG:
      return "INVALID_MSG";
      break;
    case PEX_RTMP_SERVER_STATUS_NOT_SUPPORTED:
      return "NOT_SUPPORTED";
      break;
    case PEX_RTMP_SERVER_STATUS_HANDSHAKE_PROCESS_FAILED:
      return "HANDSHAKE_PROCESS_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_HANDSHAKE_VERIFY_FAILED:
      return "HANDSHAKE_VERIFY_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_HANDSHAKE_PLAINTEXT_FAILED:
      return "HANDSHAKE_PLAINTEXT_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_TCP_CONNECT_FAILED:
      return "TCP_CONNECT_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_SSL_CONNECT_FAILED:
      return "SSL_CONNECT_FAILED";
      break;
    case PEX_RTMP_SERVER_STATUS_PARSE_FAILED:
      return "PARSE_FAILED";
      break;
    default:
      return "UNKNOWN (This should not happen. Please report it)";
      break;
  }
}
