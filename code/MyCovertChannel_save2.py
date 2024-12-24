from CovertChannelBase import CovertChannelBase
import scapy
import random
import time
import math
import collections
import io

class MyCovertChannel(CovertChannelBase):

    def __init__(self):
        # no need to initialize the base class since it is empty

        # declare if random seed set and intervals decided flag
        self.random_seed_and_intervals_set_send = False
        self.random_seed_and_intervals_set_receive = False




    def send(
        self,
        max_length : int,
        min_length : int,
        bits_per_packet : int,
        sleep_between_packets : float = 0.1,
        randomize_borders : str = "True",
        randomize_interval_order : str = "True",
        random_seed : int = 42,
        verbose : int = 0,
        log_file_name : str = "Example_UDPTimingInterarrivalChannelSender.log",
        dst_port: int = 42424,
        receiver_ip_address: str = "172.18.0.3",
    ):
        if verbose >= 1:
            # start timer for initial time
            start_time_init = time.time()

        # check if the given parameters are valid
        assert max_length > 0, "max_length must be bigger than 0"
        assert min_length > 0, "min_length must be bigger than 0"
        assert min_length <= max_length, "min_length must be smaller than or equal to max_length"

        assert bits_per_packet > 0, "bits_per_packet must be bigger than 0"
        assert bits_per_packet <= 16, "bits_per_packet must be smaller than or equal to 16"

        assert randomize_borders == "True" or randomize_borders == "False", "randomize_borders must be either True or False as a string"

        assert randomize_interval_order == "True" or randomize_interval_order == "False", "randomize_interval_order must be either True or False as a string"

        assert verbose >= 0 or verbose >= 1 or verbose >= 2 or verbose >= 3, "verbose must be 0, 1, 2 or 3"



        # create the ip packet
        ip_packet = scapy.all.IP(dst = receiver_ip_address)


        # convert boolean values from string to boolean
        randomize_borders = randomize_borders == "True"
        randomize_interval_order = randomize_interval_order == "True"

        binary_message = self.generate_random_binary_message_with_logging(
            log_file_name = log_file_name ,
            min_length = min_length,
            max_length = max_length
        )

        # initialize the intervals
        if not self.random_seed_and_intervals_set_send:
            self.init_intervals(
                bits_per_packet = bits_per_packet,
                random_seed = random_seed,
                sender_receiver_type = 0,
                randomize_borders = randomize_borders,
                randomize_interval_order = randomize_interval_order,
                verbose = verbose
            )

            self.random_seed_and_intervals_set_send = True
        
        # if binary message is not divisible by bits_per_packet, pad with zeros
        if len(binary_message) % bits_per_packet != 0:
            binary_message_padded = binary_message + "0" * (bits_per_packet - len(binary_message) % bits_per_packet)
        else:
            binary_message_padded = binary_message
        

        if verbose >= 1:
            end_time_init = time.time()
            print(f"Initialization time: {(end_time_init - start_time_init) * 1000} ms")

        # iterate over the binary message and send each bit as a UDP packet
        for i in range(0, len(binary_message_padded), bits_per_packet):
            # get the bits
            bits = binary_message_padded[i:i+bits_per_packet]

            # define the source port number
            src_port = self.get_source_port_encrypted(bits)

            # define the UDP packet
            udp_packet = scapy.all.TCP(sport = src_port, dport = dst_port)

            # send the packet (use the send function from the base class, not the scapy send function or this send function)
            super().send(ip_packet/udp_packet)


            if verbose >= 2:
                print(f"Sent bits: {bits} with source port: {src_port}")
                

            time.sleep(sleep_between_packets)
        
        if verbose >= 2:
            print(f"Sent full message binary: {binary_message}")

            print(f"Sent full message characters: \"", end="")
            
            for i in range(0, len(binary_message), 8):
                print(self.convert_eight_bits_to_character(binary_message[i:i+8]), end="")
            print("\"")


    def receive(
        self,
        bits_per_packet : int,
        timeout_tolerance : float = 0.04,
        buffer_max_tolerance_bytes : int = 1000,
        randomize_borders : str = "True",
        randomize_interval_order : str = "True",
        random_seed : int = 42,
        verbose : int = 0,
        log_file_name: str = "Example_UDPTimingInterarrivalChannelReceiver.log",
        dst_port: int = 42424,
    ):
        if verbose >= 1:
            # start timer for initial time
            start_time_init = time.time()
        
        # check if the given parameters are valid
        assert bits_per_packet > 0, "bits_per_packet must be bigger than 0"
        assert bits_per_packet <= 16, "bits_per_packet must be smaller than or equal to 16"

        assert randomize_borders == "True" or randomize_borders == "False", "randomize_borders must be either True or False as a string"
        assert randomize_interval_order == "True" or randomize_interval_order == "False", "randomize_interval_order must be either True or False as a string"

        assert verbose >= 0 or verbose >= 1 or verbose >= 2 or verbose >= 3, "verbose must be 0, 1, 2 or 3"

        # set the dst port
        self.dst_port = dst_port

        # set verbose
        self.verbose = verbose


        # convert boolean values from string to boolean
        randomize_borders = randomize_borders == "True"
        randomize_interval_order = randomize_interval_order == "True"

        # initialize the intervals
        if not self.random_seed_and_intervals_set_receive:
            self.init_intervals(
                bits_per_packet = bits_per_packet,
                random_seed = random_seed,
                sender_receiver_type = 1,
                randomize_borders = randomize_borders,
                randomize_interval_order = randomize_interval_order,
                verbose = verbose
            )

            self.random_seed_and_intervals_set_receive = True

        # receive the packets and decode the message
        message = ""

        bitcounter = 0

        bits_buffer = []

        packet_buffer = []

        bits_buffer_str = ""

        if verbose >= 1:
            end_time_init = time.time()
            print(f"Initialization time: {(end_time_init - start_time_init) * 1000} ms")
            print("Receiving...")

        # declare the timeout flag
        timeout_flag = False

        # calculate the buffer max tolerance in bits
        buffer_max_tolerance = buffer_max_tolerance_bytes * 8

        while True:
            
            # check if a full byte is received
            if (timeout_flag):
                # if the time since the not enough time passed since the last packet arrival (4 times the sleep time)
                pass # do not receive the next input, try to process if there is any packet in the buffer
            else:
                # sniff the packets
                packets = scapy.all.sniff(filter=f"tcp and dst port {dst_port}", count=1, timeout=timeout_tolerance)

                if verbose >= 2:
                    print(f"type:{type(packets)}, packets: {packets}")

                if len(packets) == 0:
                    # if no packet is received (timeout)

                    # set the timeout flag
                    timeout_flag = True

                    # continue to the next iteration
                    continue
                
                packet_buffer.append(packets[0])

                continue
            

            

            
            # if the buffer is not empty, process the packets
            while len(packet_buffer) > 0:
                if verbose >= 1:
                    timer_start_receive = time.time()

                # get the source port number
                src_port = packet_buffer.pop(0)[scapy.all.TCP].sport
                if verbose >= 1:
                    timer_end_get_src_port = time.time()
                    print(f"Get src port time: {(timer_end_get_src_port - timer_start_receive) * 1000} ms")


                # decrypt the message and add it to the buffer
                bits_buffer.append(self.get_decrypted_message_from_encrypted_source_port(src_port))
                if verbose >= 1:
                    timer_end_decrypt = time.time()
                    print(f"Decrypt time: {(timer_end_decrypt - timer_end_get_src_port) * 1000} ms")

                # increment the counter
                bitcounter += bits_per_packet

                if verbose >= 1:
                    timer_end_receive = time.time()
                    print(f"Write to buffer time: {(timer_end_receive - timer_start_receive) * 1000} ms")

                if verbose >= 2:
                    print(f"Received bits: {bits_buffer[-bits_per_packet:]} with source port: {src_port}")
                    print(f"New buffer: {bits_buffer}\n")


            # check if enough bits are received (at least 8 bits)
            if bitcounter < 8:
                # reset the timeout flag
                timeout_flag = False
                # continue to the next iteration
                continue

            if verbose >= 1:
                timer_start_process = time.time()
                
            # convert the buffer to a string
            if len(bits_buffer) > 0:
                # convert the buffer to a string
                bits_buffer_str += "".join(bits_buffer)

                # clear the buffer
                bits_buffer = []

            # convert the message to a character
            current_byte, bits_buffer_str = self.convert_eight_bits_to_character(bits_buffer_str[:8]), bits_buffer_str[8:]


            # check if the communication is finished
            if current_byte == ".":
                if verbose >= 2:
                    print("\n\nCommunication finished (received \".\")\n\n")
                break

            # add the character to the message
            message += current_byte

            # decrement the counter
            bitcounter -= 8


            if verbose >= 1:
                timer_end_process = time.time()
                print(f"Process time: {(timer_end_process - timer_start_process) * 1000} ms")

            if verbose >= 2:
                print(f"Received character: {current_byte}")
                print(f"New buffer: {bits_buffer_str}\n")
            

        if verbose >= 1:
            print(f"Received full message: \"{message}\"")


        self.log_message(message, log_file_name)
        


    def convert_integer_to_binary_string(
        self,
        number : int,
        length : int
    ):
        return bin(number)[2:].zfill(length)

    def init_intervals(
        self,
        bits_per_packet : int,
        random_seed : int,
        sender_receiver_type : int,
        randomize_borders : bool = True,
        randomize_interval_order : bool = True,
        verbose : int = 0
    ):
        # calculate the number of intervals (2^bits_per_packet)
        self.number_of_intervals = 2 ** bits_per_packet

        # declare the intervals
        # First interval: [0, src_port_interval_borders[0])
        # Second interval: [src_port_interval_borders[0], src_port_interval_borders[1])
        # Third interval: [src_port_interval_borders[1], src_port_interval_borders[2])
        # Fourth interval: [src_port_interval_borders[2], src_port_interval_borders[3])]
        # ...
        # last interval: [src_port_interval_borders[n-1], 65535]

        # apply the random seed
        random.seed(random_seed)

        # define the intervals values (there has to be n+1 borders for n intervals)
        if randomize_borders: # if the borders are randomized
            # sample non repeating random numbers
            src_port_interval_borders = random.sample(range(1, 65536), self.number_of_intervals - 1)

            # sort the borders
            src_port_interval_borders.sort()

            # add 0 and 65535 as the first and last borders
            src_port_interval_borders.insert(0, 0)
            src_port_interval_borders.append(65535)
        else: # if the borders are not randomized
            # uniformly distribute borders
            src_port_interval_borders = [i * (65535 // self.number_of_intervals) for i in range(self.number_of_intervals)]

            # add last border
            src_port_interval_borders.append(65535)
            
            

        

        # define the interval order
        self.interval_order_normal = range(self.number_of_intervals)

        # if the interval order needs to be randomized
        if randomize_interval_order:
            # shuffle the interval order to complicate encryption further
            self.interval_order = random.sample(self.interval_order_normal, self.number_of_intervals)



        # check if the sender or receiver is initializing the intervals
        if sender_receiver_type == 0 or sender_receiver_type == 2: # sender mode or both mode 
            # fill the hashmap which will be used to obtain the source port value interval using encoded bits

            # create a hashmap (key: bits as string, value: interval as a tuple of 2 integers)
            self.bits_to_source_port_value_interval = dict()

            if verbose >= 3:
                print("bits to source port value interval mapping:")

            for i in self.interval_order_normal:
                # if randomize_interval_order is true, use the randomized interval order
                if randomize_interval_order:
                    border_index = self.interval_order[i]
                else:
                    border_index = i
                

                if verbose >= 3:
                    print(f"{i}: {self.convert_integer_to_binary_string(i, bits_per_packet)} ---> [{src_port_interval_borders[border_index]}, {src_port_interval_borders[border_index+1]})")
                
                self.bits_to_source_port_value_interval[self.convert_integer_to_binary_string(i, bits_per_packet)] = (src_port_interval_borders[border_index], src_port_interval_borders[border_index+1])
        
        if verbose >= 3:
            print(f"Number of intervals: {self.number_of_intervals}")
            print(f"Interval order: \n{self.interval_order}\n")
            print(f"Interval borders: \n{src_port_interval_borders}\n")

        if sender_receiver_type == 1 or sender_receiver_type == 2: # receiver mode or both mode
            # create a list (index: source port value, value: bits as string)
            self.source_port_value_to_bits = []

            if verbose >= 3:
                print("source port value to bits mapping (samples of every 1000th source port value):")

            unrandomized_interval = 0
            # here I pre-computed all the possible source port values to avoid O(n) search for each packet in the transmission time.
            for i in range(0, 65535):
                # find the interval of the source port value
                interval = 0

                # stop the search when the interval is found
                if i > src_port_interval_borders[unrandomized_interval+1]:
                    unrandomized_interval += 1
                
                
                # if interval order is randomized, find the original interval
                if randomize_interval_order:
                    interval = self.interval_order.index(unrandomized_interval)
                else:
                    interval = unrandomized_interval


                if verbose >= 3:
                    # print every 1000th source port value for verbosing
                    if i % 1000 == 0:
                        print(f"{i} ---> {self.convert_integer_to_binary_string(interval, bits_per_packet)}")
                    

                # add the source port value and the corresponding bits to the hashmap
                self.source_port_value_to_bits.append(self.convert_integer_to_binary_string(interval, bits_per_packet))
    


    def get_source_port_encrypted(
        self,
        bit : str
    ):
        # this function assumes init_intervals is called before this function with sender_receiver_type = 0 or 2
        return random.randint(self.bits_to_source_port_value_interval[bit][0], self.bits_to_source_port_value_interval[bit][1])
    
    def get_decrypted_message_from_encrypted_source_port(
        self,
        src_port : int
    ):
        # this function assumes init_intervals is called before this function with sender_receiver_type = 1 or 2
        return self.source_port_value_to_bits[src_port]
        
    
