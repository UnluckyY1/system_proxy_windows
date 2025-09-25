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

namespace system_proxy
{

  void SystemProxyPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarWindows *registrar)
  {
    auto channel =
        std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
            registrar->messenger(), "system_proxy",
            &flutter::StandardMethodCodec::GetInstance());

    auto plugin = std::make_unique<SystemProxyPlugin>();

    channel->SetMethodCallHandler(
        [plugin_pointer = plugin.get()](const auto &call, auto result)
        {
          plugin_pointer->HandleMethodCall(call, std::move(result));
        });

    registrar->AddPlugin(std::move(plugin));
  }

  SystemProxyPlugin::SystemProxyPlugin() {}
  SystemProxyPlugin::~SystemProxyPlugin() {}

  // Helper function for formatted debug output
  void DebugLog(const std::string &message)
  {
    OutputDebugStringA(("[SystemProxy] " + message + "\n").c_str());
  }

  void DebugLog(const std::wstring &message)
  {
    OutputDebugStringA("[SystemProxy] ");
    OutputDebugStringW((message + L"\n").c_str());
  }

  template <typename... Args>
  void DebugLogFormat(const char *format, Args... args)
  {
    char buffer[1024];
    sprintf_s(buffer, sizeof(buffer), format, args...);
    OutputDebugStringA(("[SystemProxy] " + std::string(buffer) + "\n").c_str());
  }

  std::string WideToUTF8(LPCWSTR wideStr)
  {
    if (!wideStr)
      return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &result[0], size, nullptr, nullptr);
    return result.c_str();
  }

  std::wstring UTF8ToWide(const std::string &utf8Str)
  {
    if (utf8Str.empty())
      return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, nullptr, 0);
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, &result[0], size);
    return result.c_str();
  }

  std::string GetFirstProxyFromString(const std::string &proxyStr)
  {
    std::istringstream stream(proxyStr);
    std::string proxy;

    while (std::getline(stream, proxy, ';'))
    {
      size_t eqPos = proxy.find('=');
      if (eqPos != std::string::npos)
      {
        proxy = proxy.substr(eqPos + 1);
      }

      if (!proxy.empty() && proxy.find('<') == std::string::npos)
      {
        return proxy;
      }
    }
    return "";
  }

  std::string GetEffectiveProxy(const std::string &targetUrl)
  {
    HINTERNET hSession = nullptr;
    WINHTTP_PROXY_INFO proxyInfo = {0};
    WINHTTP_AUTOPROXY_OPTIONS options = {0};
    std::string proxyResult;

    // 1. Initialize options to zero
    ZeroMemory(&options, sizeof(options));
    ZeroMemory(&proxyInfo, sizeof(proxyInfo));

    DebugLog("Initializing proxy detection...");

    // 2. Open WinHTTP session
    hSession = WinHttpOpen(L"Flutter System Proxy/1.0",
                           WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS,
                           0);
    if (!hSession)
    {
      DWORD error = GetLastError();
      DebugLogFormat("WinHttpOpen failed: %lu", error);
      return "";
    }

    // Set timeouts to avoid hanging
    WinHttpSetTimeouts(hSession, 10000, 10000, 30000, 30000);

    // 3. Configure PAC/auto-detection with error handling
    HKEY hKey = nullptr;
    LSTATUS regStatus = RegOpenKeyExW(HKEY_CURRENT_USER,
                                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                                      0, KEY_READ, &hKey);

    if (regStatus == ERROR_SUCCESS)
    {
      WCHAR pacUrl[2048] = {0};
      DWORD dwSize = sizeof(pacUrl);
      DWORD dwType = 0;

      regStatus = RegQueryValueExW(hKey, L"AutoConfigURL", NULL, &dwType,
                                   (LPBYTE)pacUrl, &dwSize);

      if (regStatus == ERROR_SUCCESS && dwType == REG_SZ && pacUrl[0] != L'\0')
      {
        // Explicitly configured PAC script
        options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
        options.lpszAutoConfigUrl = pacUrl;
        options.fAutoLogonIfChallenged = TRUE;
        DebugLogFormat("Using PAC URL: %ls", pacUrl);
      }
      else
      {
        // WPAD auto-detection
        options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
        options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        options.fAutoLogonIfChallenged = TRUE;
        DebugLog("Using auto-detection");
      }
      RegCloseKey(hKey);
    }
    else
    {
      // Fallback to auto-detection if registry access fails
      options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
      options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
      options.fAutoLogonIfChallenged = TRUE;
      DebugLog("Registry open failed, using auto-detection");
    }

    // 4. Convert target URL to wide string
    std::wstring wideTargetUrl = UTF8ToWide(targetUrl);
    DebugLogFormat("Getting proxy for: %ls", wideTargetUrl.c_str());

    // 5. Get proxy configuration for target URL
    BOOL success = WinHttpGetProxyForUrl(hSession, wideTargetUrl.c_str(),
                                         &options, &proxyInfo);

    if (success)
    {
      if (proxyInfo.lpszProxy && proxyInfo.lpszProxy[0] != L'\0')
      {
        std::string proxyStr = WideToUTF8(proxyInfo.lpszProxy);
        DebugLogFormat("Proxy found: %s", proxyStr.c_str());
        proxyResult = GetFirstProxyFromString(proxyStr);
        GlobalFree(proxyInfo.lpszProxy);
      }
      else
      {
        DebugLog("No proxy required (DIRECT)");
      }

      if (proxyInfo.lpszProxyBypass)
      {
        GlobalFree(proxyInfo.lpszProxyBypass);
      }
    }
    else
    {
      DWORD error = GetLastError();
      DebugLogFormat("WinHttpGetProxyForUrl failed: %lu", error);

      // Common error codes for debugging
      if (error == ERROR_WINHTTP_AUTODETECTION_FAILED)
      {
        DebugLog("Auto-detection failed");
      }
      else if (error == ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT)
      {
        DebugLog("Bad PAC script");
      }
      else if (error == ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT)
      {
        DebugLog("Unable to download PAC script");
      }
      else if (error == ERROR_WINHTTP_LOGIN_FAILURE)
      {
        DebugLog("Proxy authentication required");
      }
      else if (error == ERROR_WINHTTP_TIMEOUT)
      {
        DebugLog("Proxy detection timeout");
      }
    }

    // 6. Cleanup
    WinHttpCloseHandle(hSession);

    if (proxyResult.empty())
    {
      DebugLog("Proxy detection completed: No proxy (DIRECT)");
    }
    else
    {
      DebugLogFormat("Proxy detection completed: %s", proxyResult.c_str());
    }

    return proxyResult;
  }

  void SystemProxyPlugin::HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result)
  {
    if (method_call.method_name() == "getProxySettings")
    {
      DebugLog("=== getProxySettings called ===");

      // Set default URL
      std::string targetUrl = "https://www.microsoft.com";

      // Extract target URL from arguments
      const auto *arguments = std::get_if<flutter::EncodableMap>(method_call.arguments());
      if (arguments)
      {
        auto urlIt = arguments->find(flutter::EncodableValue("targetUrl"));

        if (urlIt != arguments->end())
        {
          targetUrl = std::get<std::string>(urlIt->second);
          DebugLogFormat("Custom target URL: %s", targetUrl.c_str());
        }
        else
        {
          DebugLogFormat("Using default URL: %s", targetUrl.c_str());
        }
      }

      flutter::EncodableMap proxyData;
      WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieConfig = {0};
      BOOL hasIEConfig = WinHttpGetIEProxyConfigForCurrentUser(&ieConfig);

      DebugLogFormat("WinHttpGetIEProxyConfigForCurrentUser: %s", hasIEConfig ? "SUCCESS" : "FAILED");

      // 1. Get AutoConfig URL (PAC file)
      if (hasIEConfig && ieConfig.lpszAutoConfigUrl)
      {
        std::string autoConfigUrl = WideToUTF8(ieConfig.lpszAutoConfigUrl);
        DebugLogFormat("IE AutoConfigURL: %s", autoConfigUrl.c_str());
        proxyData[flutter::EncodableValue("autoConfigUrl")] =
            flutter::EncodableValue(autoConfigUrl);
        GlobalFree(ieConfig.lpszAutoConfigUrl);
      }

      // 2. Get effective proxy using WinHTTP
      std::string effectiveProxy = GetEffectiveProxy(targetUrl);
      DebugLogFormat("Effective proxy result: %s", effectiveProxy.c_str());

      // 3. Fallback to IE proxy if WinHTTP detection failed
      if (effectiveProxy.empty() && hasIEConfig && ieConfig.lpszProxy)
      {
        std::string ieProxy = WideToUTF8(ieConfig.lpszProxy);
        DebugLogFormat("Fallback to IE proxy: %s", ieProxy.c_str());
        effectiveProxy = GetFirstProxyFromString(ieProxy);
        GlobalFree(ieConfig.lpszProxy);
      }

      // 4. Set proxy value if found
      if (!effectiveProxy.empty())
      {
        proxyData[flutter::EncodableValue("proxy")] =
            flutter::EncodableValue(effectiveProxy);
        DebugLogFormat("Final proxy set: %s", effectiveProxy.c_str());
      }
      else
      {
        DebugLog("No proxy configured (DIRECT connection)");
      }

      // 5. Get proxy bypass list
      if (hasIEConfig && ieConfig.lpszProxyBypass)
      {
        std::string proxyBypass = WideToUTF8(ieConfig.lpszProxyBypass);
        DebugLogFormat("Proxy bypass: %s", proxyBypass.c_str());
        proxyData[flutter::EncodableValue("proxyBypass")] =
            flutter::EncodableValue(proxyBypass);
        GlobalFree(ieConfig.lpszProxyBypass);
      }

      DebugLogFormat("Returning proxy data with %zu entries", proxyData.size());
      result->Success(proxyData);
    }
    else
    {
      DebugLogFormat("Unknown method called: %s", method_call.method_name().c_str());
      result->NotImplemented();
    }
  }

} // namespace system_proxy