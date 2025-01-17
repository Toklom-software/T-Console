using System.Net;
using System.Text.RegularExpressions;


namespace ProxyParser
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.Clear(); 

            while (true) 
            {
                Console.Write("root@toklom -# ");
                string? command = Console.ReadLine();

                if (string.IsNullOrEmpty(command))
                {
                    continue;
                }

                string[] commandParts = command.Split(' ');

                switch (commandParts[0])
                {
                    case "help":
                        ShowHelp();
                        break;
                    case "clear":
                    case "cls":
                        Console.Clear();
                        break;
                    case "check":
                        await CheckProxies();
                        break;
                    case "exit":
                        return; // Выход из программы
                    default:
                        Console.WriteLine("Неизвестная команда. Используйте 'help' для списка команд.");
                        break;
                }
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine("Доступные команды:");
            Console.WriteLine("  help - Показать это справочное сообщение");
            Console.WriteLine("  clear или cls - Очистить консоль");
            Console.WriteLine("  check - Начать проверку прокси");
            Console.WriteLine("  exit - Выйти из программы");
        }

        static async Task CheckProxies()
        {
            string logsFile = "logs.txt";

            List<string> proxyListUrls = new List<string>()
            {
                "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
                "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
                "https://raw.githubusercontent.com/jetkai/proxy-list/main/online/http.txt",
                "https://raw.githubusercontent.com/clarketm/proxy-list/main/proxy-list-raw.txt",
                "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
                "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
                "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_RAW.txt",
                "https://proxyspace.pro/http.txt",
                "https://www.proxy-list.download/api/v1/get?type=http",
                "https://proxylist.geonode.com/api/proxy-locations?limit=500&page=1&sort_by=last_check&sort_type=desc",
                "https://www.freeproxychecker.com/result/?type=http",
                "https://multiproxy.org/txt_all/proxy.txt",
                "https://openproxy.space/list/http",
                "https://spys.me/proxy.txt",
                "https://www.my-proxy.com/free-proxy-list.html",
                "https://free-proxy-list.net/",
                "https://hidemy.name/en/free-proxy-list/",
                "https://proxygather.com/download/http",
                "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
                "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
                "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
                "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt",
                "https://raw.githubusercontent.com/ShuRen-Li/proxy-list/main/http.txt",
                "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
                "https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt",
                "https://raw.githubusercontent.com/KUTlime/ProxyList/main/http.txt",
                "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
                "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
                "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt"
            };

            HashSet<string> allProxies = new HashSet<string>();

            Console.WriteLine("Не забудьте подписаться на наш основной канал https://t.me/adaprter");

            using (HttpClient client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromSeconds(5);

                var tasks = proxyListUrls.Select(async url =>
                {
                    try
                    {
                        HttpResponseMessage response = await client.GetAsync(url);
                        if (response.IsSuccessStatusCode)
                        {
                            string content = await response.Content.ReadAsStringAsync();
                            if (url.Contains("geonode") || url.Contains("proxyhub"))
                            {
                                try
                                {
                                    var json = System.Text.Json.JsonDocument.Parse(content);
                                    var data = json.RootElement.GetProperty("data").EnumerateArray();
                                    foreach (var item in data)
                                    {
                                        string ip = item.GetProperty("ip").GetString();
                                        int port = item.GetProperty("port").GetInt32();
                                        string proxy = $"{ip}:{port}";
                                        if (IsValidProxyFormat(proxy))
                                        {
                                            allProxies.Add(proxy);
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Ошибка {url}: {ex.Message}");
                                }
                            }
                            else if (url.Contains("freeproxychecker"))
                            {
                                Regex regex = new Regex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+");
                                foreach (Match match in regex.Matches(content))
                                {
                                    if (IsValidProxyFormat(match.Value))
                                    {
                                        allProxies.Add(match.Value);
                                    }
                                }
                            }
                            else if (url.Contains("openproxy.space"))
                            {
                                Regex regex = new Regex(@"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})");
                                foreach (Match match in regex.Matches(content))
                                {
                                    string proxy = $"{match.Groups[1].Value}:{match.Groups[2].Value}";
                                    if (IsValidProxyFormat(proxy))
                                    {
                                        allProxies.Add(proxy);
                                    }
                                }
                            }
                            else if (url.Contains("spys.me"))
                            {
                                Regex regex = new Regex(@"<td[^\>]*>([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})<\/td>.*?<font class=spy2>(.+?)<script");
                                foreach (Match match in regex.Matches(content))
                                {
                                    string ip = match.Groups[1].Value;
                                    string encodedPort = match.Groups[2].Value;
                                    string decodedPort = "";

                                    if (encodedPort.Contains("+"))
                                    {
                                        string[] parts = encodedPort.Split('+');
                                        foreach (string part in parts)
                                        {
                                            if (part.Contains("^"))
                                            {
                                                string[] subParts = part.Split('^');
                                                if (subParts.Length == 2)
                                                {
                                                    decodedPort += (int.Parse(subParts[0]) ^ int.Parse(subParts[1])).ToString();
                                                }
                                            }
                                            else
                                            {
                                                decodedPort += part;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        decodedPort = new string(encodedPort.Where(char.IsDigit).ToArray());
                                    }

                                    if (!string.IsNullOrEmpty(decodedPort))
                                    {
                                        string proxy = $"{ip}:{decodedPort}";
                                        if (IsValidProxyFormat(proxy))
                                        {
                                            allProxies.Add(proxy);
                                        }
                                    }
                                }
                            }
                            else if (url.Contains("my-proxy.com"))
                            {
                                Regex regex = new Regex(@"<td>([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})</td>[\s\S]*?<td>([0-9]{1,5})</td>");
                                foreach (Match match in regex.Matches(content))
                                {
                                    string proxy = $"{match.Groups[1].Value}:{match.Groups[2].Value}";
                                    if (IsValidProxyFormat(proxy))
                                    {
                                        allProxies.Add(proxy);
                                    }
                                }
                            }
                            else if (url.Contains("free-proxy-list.net"))
                            {
                                Regex regex = new Regex(@"<td>([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})</td><td>([0-9]{1,5})</td>");
                                foreach (Match match in regex.Matches(content))
                                {
                                    string proxy = $"{match.Groups[1].Value}:{match.Groups[2].Value}";
                                    if (IsValidProxyFormat(proxy))
                                    {
                                        allProxies.Add(proxy);
                                    }
                                }
                            }
                            else if (url.Contains("hidemy.name"))
                            {
                                Regex regex = new Regex(@"<td class=""tdl"">([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})</td>[\s\S]*?<td[^>]*>([0-9]{1,5})</td>");
                                foreach (Match match in regex.Matches(content))
                                {
                                    string proxy = $"{match.Groups[1].Value}:{match.Groups[2].Value}";
                                    if (IsValidProxyFormat(proxy))
                                    {
                                        allProxies.Add(proxy);
                                    }
                                }
                            }
                            else
                            {
                                foreach (var line in content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                                {
                                    string proxy = line.Trim();
                                    if (IsValidProxyFormat(proxy))
                                    {
                                        allProxies.Add(proxy);
                                    }
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Не удалось загрузить прокси с {url}.");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Ошибка при загрузке прокси с {url}: {ex.Message}");
                    }
                });
                await Task.WhenAll(tasks);
            }

            Console.WriteLine($"Найдено {allProxies.Count} уникальных прокси. Начинаю проверку...");

            List<string> validProxies = new List<string>();
            ServicePointManager.DefaultConnectionLimit = 500;

            using (var httpClient = new HttpClient(new HttpClientHandler { Proxy = new WebProxy(), UseProxy = false }))
            {
                httpClient.Timeout = TimeSpan.FromSeconds(5);

                var tasks = allProxies.Select(async proxyAddress =>
                {
                    try
                    {
                        using (var handler = new HttpClientHandler
                        {
                            Proxy = new WebProxy(proxyAddress),
                            ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
                        })
                        {
                            using (var client = new HttpClient(handler))
                            {
                                client.Timeout = TimeSpan.FromSeconds(10);

                                var response = await client.GetAsync("http://www.google.com");

                                if (response.IsSuccessStatusCode)
                                {
                                    lock (validProxies)
                                    {
                                        validProxies.Add(proxyAddress);
                                    }
                                    Console.WriteLine($"Прокси {proxyAddress} валиден.");
                                }
                                else
                                {
                                    Console.WriteLine($"Прокси {proxyAddress} не валиден.");
                                }
                            }
                        }
                    }
                    catch (Exception)
                    {
                        Console.WriteLine($"Прокси {proxyAddress} не валиден или недоступен.");
                    }
                });

                await Task.WhenAll(tasks);
            }

            try
            {
                await File.WriteAllLinesAsync(logsFile, validProxies);
                Console.WriteLine($"Прокси записаны в {logsFile}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при записи в файл {logsFile}: {ex.Message}");
            }
        }

        static bool IsValidProxyFormat(string proxy)
        {
            string pattern = @"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$";
            return Regex.IsMatch(proxy, pattern);
        }
    }
}