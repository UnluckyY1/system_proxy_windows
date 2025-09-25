import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';

class SystemProxy {
  static const MethodChannel _channel = const MethodChannel('system_proxy');

  /// get system proxy
  /// Has fixed proxy, return: {port: 8899, host: 172.24.141.93}
  /// Has automatic proxy, return: {url: http://example.com/wpad.dat}
  /// no proxy, return: null
  ///
  static Future<Map<String, String>?> getProxySettings(
      {String? targetUrl}) async {
    if (Platform.isWindows) {
      Map<String, String> result = {};

      // Map Keys
      //
      // see https://learn.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_current_user_ie_proxy_config#members
      //
      // autoConfigUrl is lpszAutoConfigUrl
      // proxy is lpszProxy
      // proxyBypass is lpszProxyBypass
      final String effectiveUrl = targetUrl ?? "https://www.microsoft.com";

      final Map<Object?, Object?> proxySettingMap = await _channel
          .invokeMethod<dynamic>(
              'getProxySettings', {'targetUrl': effectiveUrl});

      if (proxySettingMap['autoConfigUrl'] != null) {
        result['url'] = proxySettingMap['autoConfigUrl'].toString();
      }
      if (proxySettingMap['proxy'] != null) {
        final proxySplit = proxySettingMap['proxy'].toString().split(':');
        if (0 < proxySplit.length) {
          result['host'] = proxySplit[0];
        }
        if (1 < proxySplit.length) {
          result['port'] = proxySplit[1];
        }
      }
      if (proxySettingMap['proxyBypass'] != null) {}

      if (result.length == 0) {
        return null;
      } else {
        return result;
      }
    }
    return null;
  }
}
