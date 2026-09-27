#pragma once
#include <functional>
#include <string>
#include <winrt/Windows.UI.Notifications.h>
#include <winrt/Windows.Data.Xml.Dom.h>

class AppToastNotifier {
public:
    static void Initialize(const std::wstring& aumid);
    static void ShowDetectionToast(const std::wstring& detectionState, const std::wstring& fileName, const std::wstring& filePath, const std::wstring& argument);
    static void SetActivatedCallback(std::function<void(std::wstring)> callback);

private:
    static std::wstring aumid_;
    static std::function<void(std::wstring)> activatedCallback_;
};