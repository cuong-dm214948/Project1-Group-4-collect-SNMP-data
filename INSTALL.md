
# môi trường cài đặt: 

window,linux

# thư viện sử dụng:

https://ireasoning.com/mibbrowser.shtml

https://www.snmp4j.org/

# cách cài đặt và triển khai:

Hầu hết các thiết bị mạng được cung cấp đi kèm với SNMP agent. Các agent này phải được kích hoạt và cấu hình để giao tiếp với các công cụ giám sát mạng hoặc hệ thống quản lý mạng (NMS). Trình quản lý hoặc hệ thống quản lý (SMNP manager) là một phần mềm được cài đặt trên máy tính của người quản trị mạng và chịu trách nhiệm giám sát và điều khiển các thiết bị mạng từ xa. Việc kích hoạt agent cho phép nó thu thập cơ sở dữ liệu thông tin quản lý từ thiết bị cục bộ và cung cấp nó cho SNMP manager khi được truy vấn. Thiết bị được quản lý hoặc phần tử mạng là một phần của mạng yêu cầu một số hình thức giám sát và quản lý (ví dụ: router, switches, server, máy trạm, máy in, UPS, v.v.)

Agent lưu trữ thông tin về các thiết bị mạng trong một cơ sở dữ liệu gọi là MIB (Management Information Base) được biểu diễn trong một cấu trúc cây có các node nhận dạng cho từng OID (chứa mã số và thông tin cung cấp).Để nhận thông tin trạng thái từ Snmp agent, Snmp manager có thể đưa ra message để yêu cầu thông tin cho một node cụ thể (getRequest). Sau khi nhận được message, Snmp agent sẽ gửi message getResponse cho Snmp manager. Nó sẽ chứa thông tin được yêu cầu hoặc lỗi giải thích tại sao không thể xử lý yêu cầu.

Các phươn thức hoạt động bao gồm:
+ Snmp GetRequest được manager gửi đến agent để lấy một thông tin của một node cụ thể (chứa OID của object muốn lấy)
VD: GetRequest OID=1.3.6.1.2.1.1.0 sẽ nhận được thông tin về tên đầy đủ và nhận dạng phiên bản của loại phần cứng của hệ thống, hệ điều hành phần mềm và phần mềm mạng.

+ Snmp GetNextRequest cũng dùng để lấy thông tin tuy nhiên nó dùng để lấy thông tin của object nằm kế tiếp object được chỉ ra.
VD: GetNextRequest OID=1.3.6.1.2.1.1.0 sẽ nhận được thông tin về nhận dạng có thẩm quyền của nhà cung cấp (nếu nhà cung cấp có thể gán định danh 1.3.6.1.4.1.424242.1.1) chứa OID=1.3.6.1.2.1.1.1.

+ SNMPwalk sử dụng nhiều request Get-Next để truy xuất toàn bộ cây dữ liệu mạng từ một đối tượng được quản lý.
VD: Snmp walk OID=1.3.6.1.2.1.1 sẽ nhận được thông tin về mô tả hệ thống(OID=1.3.6.1.2.1.1.0); nhận dạng nhà cung cấp (OID=1.3.6.1.2.1.1.0); mô tả thời gian khi phần quản lý mạng cuối cùng khởi tạo lại (OID=1.3.6.1.2.1.1.1); nhận dạng người liên hệ(OID=1.3.6.1.2.1.1.2) tên hệ thống(OID=1.3.6.1.2.1.1.4)...

+ Message TRAP tạo bởi agent và gửi đến manager khi một sự kiện quan trọng xảy ra (cảnh báo cho manager) thay vì đợi yêu cầu từ manager.



