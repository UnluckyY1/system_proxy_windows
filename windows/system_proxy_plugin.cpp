#include "system_proxy_plugin.h"

#include <windows.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <WinHttp.h>
#include <string>
#include <vector>
#include <sstream>
#pragma comment(lib, "winhttp")

namespace system_proxy {

void SystemProxyPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows* registrar) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "system_proxy",
          &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<SystemProxyPlugin>();

  channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto& call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });

  registrar->AddPlugin(std::move(plugin));
}

SystemProxyPlugin::SystemProxyPlugin() {}
SystemProxyPlugin::~SystemProxyPlugin() {}

std::string WideToUTF8(LPCWSTR wideStr) {
  if (!wideStr) return "";
  int size = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
  std::string result(size, 0);
  WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &result[0], size, nullptr, nullptr);
  return result.c_str();
}

std::string GetFirstProxyFromString(const std::string& proxyStr) {
  std::istringstream stream(proxyStr);
  std::string proxy;
  
  while (std::getline(stream, proxy, ';')) {
    size_t eqPos = proxy.find('=');
    if (eqPos != std::string::npos) {
      proxy = proxy.substr(eqPos + 1);
    }
    
    if (!proxy.empty() && proxy.find('<') == std::string::npos) {
      return proxy;
    }
  }
  return "";
}

std::string GetEffectiveProxy() {
  HINTERNET hSession = WinHttpOpen(L"Flutter System Proxy/1.0",
                                  WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                  WINHTTP_NO_PROXY_NAME,
                                  WINHTTP_NO_PROXY_BYPASS, 
                                  WINHTTP_FLAG_ASYNC);
  if (!hSession) return "";

  WINHTTP_PROXY_INFO proxyInfo = {0};
  WINHTTP_AUTOPROXY_OPTIONS options = {0};
  options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
  options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | 
                             WINHTTP_AUTO_DETECT_TYPE_DNS_A;
  options.fAutoLogonIfChallenged = TRUE;

  std::string proxyResult;
  if (WinHttpGetProxyForUrl(hSession, L"http://windows.proxy.detect/",
                          &options, &proxyInfo)) {
    if (proxyInfo.lpszProxy) {
      std::string proxyStr = WideToUTF8(proxyInfo.lpszProxy);
      proxyResult = GetFirstProxyFromString(proxyStr);
      GlobalFree(proxyInfo.lpszProxy);
    }
    if (proxyInfo.lpszProxyBypass) {
      GlobalFree(proxyInfo.lpszProxyBypass);
    }
  }
  
  WinHttpCloseHandle(hSession);
  return proxyResult;
}

void SystemProxyPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue>& method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  if (method_call.method_name() == "getProxySettings") {
    flutter::EncodableMap proxyData;
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieConfig = {0};
    bool hasIEConfig = WinHttpGetIEProxyConfigForCurrentUser(&ieConfig);

    // 1. Get AutoConfig URL (PAC file)
    if (hasIEConfig && ieConfig.lpszAutoConfigUrl) {
      proxyData[flutter::EncodableValue("autoConfigUrl")] = 
          flutter::EncodableValue(WideToUTF8(ieConfig.lpszAutoConfigUrl));
      GlobalFree(ieConfig.lpszAutoConfigUrl);
    }

    // 2. Get effective proxy (automatic detection)
    std::string effectiveProxy = GetEffectiveProxy();
    
    // 3. Fallback to IE proxy if automatic detection didn't find anything
    if (effectiveProxy.empty() && hasIEConfig && ieConfig.lpszProxy) {
      std::string ieProxy = WideToUTF8(ieConfig.lpszProxy);
      effectiveProxy = GetFirstProxyFromString(ieProxy);
      GlobalFree(ieConfig.lpszProxy);
    }

    // 4. Set proxy value if found
    if (!effectiveProxy.empty()) {
      proxyData[flutter::EncodableValue("proxy")] = 
          flutter::EncodableValue(effectiveProxy);
    }

    // 5. Get proxy bypass list
    if (hasIEConfig && ieConfig.lpszProxyBypass) {
      proxyData[flutter::EncodableValue("proxyBypass")] = 
          flutter::EncodableValue(WideToUTF8(ieConfig.lpszProxyBypass));
      GlobalFree(ieConfig.lpszProxyBypass);
    }

    result->Success(proxyData);
  } else {
    result->NotImplemented();
  }
}

}  // namespace system_proxy