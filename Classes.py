from typing import List
class Ip:
    #constructor
    def __init__(self, Ip_address: str, portlist: List[str],secureportlist: List[str]):
        self.Ip_address = Ip_address
        self.portlist = portlist
    #add new open port
    def set_next_port(self, port: str):
        self.portlist.append(port)

    #returns ip address
    def get_ip(self):
        return self.Ip_address

    #returns open ports list
    def get_port_list(self):
        return self.portlist

    #prints all open ports for the ip address
    def print_ip(self):
        print("for ip number " + self.Ip_address + " these ports are open:")
        if len(self.portlist) == 0:  # הוספתי תנאי לאם יש פורטים פתוחים בכלל
            print("None")
        else:
            for port in self.portlist:
                print(port + "\n")
