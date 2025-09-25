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

    // 2. Open WinHTTP session
    hSession = WinHttpOpen(L"Flutter System Proxy/1.0",
                           WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS,
                           0);
    if (!hSession)
    {
      printf("WinHttpOpen failed: %lu\n", GetLastError());
      return "";
    }

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
        printf("Using PAC URL: %ls\n", pacUrl);
      }
      else
      {
        // WPAD auto-detection
        options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
        options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        options.fAutoLogonIfChallenged = TRUE;
        printf("Using auto-detection\n");
      }
      RegCloseKey(hKey);
    }
    else
    {
      // Fallback to auto-detection if registry access fails
      options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
      options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
      options.fAutoLogonIfChallenged = TRUE;
      printf("Registry open failed, using auto-detection\n");
    }

    // 4. Convert target URL to wide string
    std::wstring wideTargetUrl = UTF8ToWide(targetUrl);
    printf("Getting proxy for: %ls\n", wideTargetUrl.c_str());

    // 5. Get proxy configuration for target URL
    BOOL success = WinHttpGetProxyForUrl(hSession, wideTargetUrl.c_str(),
                                         &options, &proxyInfo);

    if (success)
    {
      if (proxyInfo.lpszProxy && proxyInfo.lpszProxy[0] != L'\0')
      {
        std::string proxyStr = WideToUTF8(proxyInfo.lpszProxy);
        printf("Proxy found: %s\n", proxyStr.c_str());
        proxyResult = GetFirstProxyFromString(proxyStr);
        GlobalFree(proxyInfo.lpszProxy);
      }
      else
      {
        printf("No proxy required (DIRECT)\n");
      }

      if (proxyInfo.lpszProxyBypass)
      {
        GlobalFree(proxyInfo.lpszProxyBypass);
      }
    }
    else
    {
      DWORD error = GetLastError();
      printf("WinHttpGetProxyForUrl failed: %lu\n", error);

      // Common error codes for debugging
      if (error == ERROR_WINHTTP_AUTODETECTION_FAILED)
      {
        printf("Auto-detection failed\n");
      }
      else if (error == ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT)
      {
        printf("Bad PAC script\n");
      }
      else if (error == ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT)
      {
        printf("Unable to download PAC script\n");
      }
    }

    // 6. Cleanup
    WinHttpCloseHandle(hSession);
    return proxyResult;
  }

  void SystemProxyPlugin::HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result)
  {
    if (method_call.method_name() == "getProxySettings")
    {
      printf("=== getProxySettings called ===\n");

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
          printf("Custom target URL: %s\n", targetUrl.c_str());
        }
        else
        {
          printf("Using default URL: %s\n", targetUrl.c_str());
        }
      }

      flutter::EncodableMap proxyData;
      WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieConfig = {0};
      BOOL hasIEConfig = WinHttpGetIEProxyConfigForCurrentUser(&ieConfig);

      printf("WinHttpGetIEProxyConfigForCurrentUser: %s\n", hasIEConfig ? "SUCCESS" : "FAILED");

      // 1. Get AutoConfig URL (PAC file)
      if (hasIEConfig && ieConfig.lpszAutoConfigUrl)
      {
        std::string autoConfigUrl = WideToUTF8(ieConfig.lpszAutoConfigUrl);
        printf("IE AutoConfigURL: %s\n", autoConfigUrl.c_str());
        proxyData[flutter::EncodableValue("autoConfigUrl")] =
            flutter::EncodableValue(autoConfigUrl);
        GlobalFree(ieConfig.lpszAutoConfigUrl);
      }

      // 2. Get effective proxy using WinHTTP
      std::string effectiveProxy = GetEffectiveProxy(targetUrl);
      printf("Effective proxy result: %s\n", effectiveProxy.c_str());

      // 3. Fallback to IE proxy if WinHTTP detection failed
      if (effectiveProxy.empty() && hasIEConfig && ieConfig.lpszProxy)
      {
        std::string ieProxy = WideToUTF8(ieConfig.lpszProxy);
        printf("Fallback to IE proxy: %s\n", ieProxy.c_str());
        effectiveProxy = GetFirstProxyFromString(ieProxy);
        GlobalFree(ieConfig.lpszProxy);
      }

      // 4. Set proxy value if found  ← THIS WAS MISSING!
      if (!effectiveProxy.empty())
      {
        proxyData[flutter::EncodableValue("proxy")] =
            flutter::EncodableValue(effectiveProxy);
        printf("Final proxy set: %s\n", effectiveProxy.c_str());
      }
      else
      {
        printf("No proxy configured (DIRECT connection)\n");
      }

      // 5. Get proxy bypass list
      if (hasIEConfig && ieConfig.lpszProxyBypass)
      {
        std::string proxyBypass = WideToUTF8(ieConfig.lpszProxyBypass);
        printf("Proxy bypass: %s\n", proxyBypass.c_str());
        proxyData[flutter::EncodableValue("proxyBypass")] =
            flutter::EncodableValue(proxyBypass);
        GlobalFree(ieConfig.lpszProxyBypass);
      }

      // 6. Cleanup any remaining IE config memory
      if (hasIEConfig)
      {
        // Ensure all allocated strings are freed
        if (ieConfig.lpszProxy && !effectiveProxy.empty())
        {
          // Already freed above in fallback, but if not used, free it now
          GlobalFree(ieConfig.lpszProxy);
        }
        if (ieConfig.lpszProxyBypass)
        {
          // Already freed above, but double-check
          GlobalFree(ieConfig.lpszProxyBypass);
        }
      }

      printf("Returning proxy data with %zu entries\n", proxyData.size());
      result->Success(proxyData);
    }
    else
    {
      result->NotImplemented();
    }
  }
} // namespace system_proxy