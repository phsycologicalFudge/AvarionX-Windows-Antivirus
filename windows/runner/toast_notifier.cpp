#include "toast_notifier.h"
#include <winrt/Windows.Foundation.h>
#include <shobjidl.h>

using namespace winrt::Windows::UI::Notifications;
using namespace winrt::Windows::Data::Xml::Dom;

std::wstring AppToastNotifier::aumid_;
std::function<void(std::wstring)> AppToastNotifier::activatedCallback_;

namespace {

    std::wstring EscapeXml(const std::wstring& input) {
        std::wstring out;
        out.reserve(input.size());
        for (wchar_t c : input) {
            switch (c) {
                case L'&': out += L"&amp;"; break;
                case L'<': out += L"&lt;"; break;
                case L'>': out += L"&gt;"; break;
                case L'"': out += L"&quot;"; break;
                case L'\'': out += L"&apos;"; break;
                default: out += c; break;
            }
        }
        return out;
    }

}

void AppToastNotifier::Initialize(const std::wstring& aumid) {
    aumid_ = aumid;
    SetCurrentProcessExplicitAppUserModelID(aumid.c_str());
}

void AppToastNotifier::SetActivatedCallback(std::function<void(std::wstring)> callback) {
    activatedCallback_ = std::move(callback);
}

void AppToastNotifier::ShowDetectionToast(const std::wstring& detectionState, const std::wstring& fileName, const std::wstring& filePath, const std::wstring& argument) {
    std::wstring xml =
            L"<toast launch=\"" + EscapeXml(argument) + L"\">"
                                                        L"<visual><binding template=\"ToastGeneric\">"
                                                        L"<text>" + EscapeXml(detectionState) + L"</text>"
                                                                                                L"<text>" + EscapeXml(fileName) + L"</text>"
                                                                                                                                  L"<text>" + EscapeXml(filePath) + L"</text>"
                                                                                                                                                                    L"</binding></visual>"
                                                                                                                                                                    L"<actions>"
                                                                                                                                                                    L"<action content=\"See more\" arguments=\"" + EscapeXml(argument) + L"\" activationType=\"foreground\"/>"
                                                                                                                                                                                                                                         L"</actions>"
                                                                                                                                                                                                                                         L"</toast>";

    XmlDocument doc;
    doc.LoadXml(xml);

    ToastNotification toast{doc};

    toast.Activated([](ToastNotification const&, winrt::Windows::Foundation::IInspectable const& args) {
        std::wstring arguments;
        if (auto toastArgs = args.try_as<ToastActivatedEventArgs>()) {
            arguments = toastArgs.Arguments().c_str();
        }
        if (activatedCallback_) {
            activatedCallback_(arguments);
        }
    });

    auto notifier = ToastNotificationManager::CreateToastNotifier(aumid_);
    notifier.Show(toast);
}