import 'package:http/browser_client.dart';
import 'http_management_api.dart';

HttpManagementApi createManagementApi() {
  final browser = BrowserClient();
  // All requests are same-origin; never opt into cross-site credentials.
  browser.withCredentials = false;
  return HttpManagementApi(client: browser, origin: Uri.base);
}
