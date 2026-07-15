package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class MenuItemsProvider implements ContextMenuItemsProvider {

    private MontoyaApi api;

    public MenuItemsProvider() {
        //noop
    }

    public MenuItemsProvider(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItemList = new ArrayList<>();

        JMenuItem pasteItem = new JMenuItem("Paste cURL command");
        pasteItem.addActionListener((ActionEvent e) -> {
            String curlRequest = getClipboardContent();
            if (curlRequest == null || curlRequest.isBlank()) {
                showError("Clipboard is empty or does not contain text.");
                return;
            }

            api.logging().logToOutput("Paste cURL: parsing clipboard content (" + curlRequest.length() + " chars)");

            HttpRequest rawRequest = parseCurlRequest(curlRequest);

            if (rawRequest != null) {
                api.repeater().sendToRepeater(rawRequest);
                api.logging().logToOutput("Paste cURL: sent request to Repeater");
            } else {
                showError("Failed to parse cURL command from clipboard.\n\n"
                        + "Ensure the clipboard contains a valid curl command with an http(s) URL.");
            }
        });

        menuItemList.add(pasteItem);
        return menuItemList;
    }

    private void showError(String message) {
        api.logging().logToError(message);
        SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(
                        null,
                        message,
                        "Paste cURL",
                        JOptionPane.ERROR_MESSAGE));
    }

    private HttpRequest parseCurlRequest(String curlCommand) {
        CurlParser.CurlRequest curlRequest = CurlParser.parseCurlCommand(curlCommand, api);

        if (curlRequest == null) {
            api.logging().logToError("Failed to parse curl command");
            return null;
        }

        HttpService service = HttpService.httpService(curlRequest.getBaseUrl());

        HttpRequest output = HttpRequest.httpRequestFromUrl(curlRequest.getBaseUrl())
                .withMethod(curlRequest.getMethod())
                .withBody(curlRequest.getBody());

        for (HttpHeader header : curlRequest.getHeaders()) {
            output = withoutHeadersNamedIgnoreCase(output, header.name());
            output = output.withHeader(header.name(), header.value());
        }

        output = output.withService(service);

        return output;
    }

    private static HttpRequest withoutHeadersNamedIgnoreCase(HttpRequest request, String headerName) {
        List<HttpHeader> toRemove = new ArrayList<>();
        for (HttpHeader h : request.headers()) {
            if (h.name().equalsIgnoreCase(headerName)) {
                toRemove.add(h);
            }
        }
        for (HttpHeader h : toRemove) {
            request = request.withRemovedHeader(h);
        }
        return request;
    }

    public String getClipboardContent() {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable transferable = clipboard.getContents(null);
        if (transferable != null && transferable.isDataFlavorSupported(DataFlavor.stringFlavor)) {
            try {
                return (String) transferable.getTransferData(DataFlavor.stringFlavor);
            } catch (UnsupportedFlavorException | IOException e) {
                api.logging().logToError(e);
            }
        }
        return "";
    }

}
