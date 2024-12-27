from CovertChannelBase import CovertChannelBase
import scapy
import random
import time
import math

class MyCovertChannel(CovertChannelBase):

    def __init__(self):
        # no need to initialize the base class since it is empty

        # declare if random seed set and intervals decided flag
        self.random_seed_and_intervals_set_send    = False
        self.random_seed_and_intervals_set_receive = False




    def send(
        self,
        max_length                                         : int,
        min_length                                         : int,
        bits_per_packet                                    : int,
        sleep_between_packets                              : float = 0.000001,
        sleep_between_packet_number_info_and_actual_message: float = 0.05,
        randomize_borders                                  : str = "True",
        randomize_interval_order                           : str = "True",
        use_additional_dynamic_shifting                    : str = "True",
        random_seed                                        : int = 42,
        verbose                                            : int = 1,
        store_packets_prior_to_sending                     : str = "True",
        integer_bit_size_to_inform_packet_count            : int = 32,
        log_file_name                                      : str = "Example_UDPTimingInterarrivalChannelSender.log",
        dst_port                                           : int = 42424,
        receiver_ip_address                                : str = "172.18.0.3",
    ):
        """
        Sends the message to the receiver. The message is encoded in the source port values of the UDP packets.

        Parameters:
        - max_length (int): the maximum length of the message to send
        - Explanation     : The maximum length of the randomly generated message to send.

        - min_length (int): the minimum length of the message to send
        - Explanation     : The minimum length of the randomly generated message to send.

        -  bits_per_packet (int): the number of bits to encode in a single packet
        -  Explanation          : The number of bits to encode in a single packet. Larger values increase the capacity of the covert channel, but tightens the intervals.
        -- restrictions         : 1 <= bits_per_packet <= 16

        -  sleep_between_packets (float) (default=0.000001): the time to sleep between sending each packet
        -  Explanation                                     : The time to sleep between sending each packet. It is used to separate the packets in time.
        -- warning                                         : too low values may cause packet loss

        -  sleep_between_packet_number_info_and_actual_message (float) (default=0.001): the time to sleep between sending the packet number information and the actual message
        -  Explanation                                                                : The time to sleep between sending the packet number information and the actual message. It is used to separate the packets in time and give the receiver time to process the packet number information.
        -- warning                                                                    : too low values may cause infinte waiting time for the receiver if initial packets after packet number information are lost.

        - randomize_borders (str) (default="True"): whether to randomize the borders of the intervals
        - Explanation                             : If True, the border values of the intervals are randomized. If False, the borders are uniformly distributed.

        - randomize_interval_order (str) (default="True"): whether to randomize the order of the intervals
        - Explanation                                    : If True, the order of the intervals is randomized. If False, the order is kept as it is (form 0 to n-1).

        - use_additional_dynamic_shifting (str) (default="True"): whether to use additional dynamic shifting
        - Explanation                                           : If True, then messages shifted to right circularly by (self.packet_counter*3 + self.packet_counter**2//3) % (self.bits_per_packet - 1) + 1 bits before encoding to source port values. If False, no shifting is applied.

        - random_seed (int) (default=42): the random seed to use for randomizing the intervals
        - Explanation                   : The random seed to use for randomizing the borders of the intervals and the interval order.

        -  verbose (int) (default=0): the verbosity level
        -- 0                        : no verbosity
        -- 1                        : print initialization time and most important information
        -- 2                        : print all information
        -- 3                        : print all information and the mapping between bits and intervals

        -  store_packets_prior_to_sending (str) (default="False"): whether to store the packets prior to sending
        -  Explanation                                           : If True, the packets are stored in a list before sending. If False, the packets are created just before sending.
        -- warning                                               : Storing packets may require additional memory. For large messages, it may consume a lot of memory and cause a wait time before sending the packets.

        -  integer_bit_size_to_inform_packet_count (int) (default=32): the number of bits to encode the number of packets to send
        -  Explanation                                               : The number of bits to encode the number of packets to send. Larger values increase the capacity of the covert channel, but tightens the intervals.
        -- restrictions                                              : integer_bit_size_to_inform_packet_count >= math.ceil(math.log2(max_length) + 3 -  math.log2(bits_per_packet))

        - log_file_name (str) (default="Example_UDPTimingInterarrivalChannelSender.log"): the name of the log file to log the sent message
        - Explanation                                                                   : The log file of the sent message will be stored in this file.

        -  dst_port (int) (default=42424): the destination port to send the packets
        -  Explanation                   : The destination port to send the packets. (to avoid sniffing wrong packets accidentally)
        -- restrictions                  : 0 <= dst_port <= 65535

        -  receiver_ip_address (str) (default="172.18.0.3"): the IP address of the receiver
        -  Explanation                                     : The IP address of the receiver to send the packets.
        -- restrictions                                    : valid IP address
        """
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

        assert random_seed >= 0, "random_seed must be bigger than or equal to 0"

        assert store_packets_prior_to_sending == "True" or store_packets_prior_to_sending == "False", "store_packets_prior_to_sending must be either True or False as a string"

        assert (integer_bit_size_to_inform_packet_count) >= math.ceil(math.log2(max_length) + 3 -  math.log2(bits_per_packet)), f"2^integer_bit_size_to_inform_packet_count must be bigger than or equal to the number of packets to send (math.ceil(math.log2(max_length) + 3 -  math.log2(bits_per_packet))) ####### Error: {integer_bit_size_to_inform_packet_count} < {math.ceil(math.log2(max_length) + 3 -  math.log2(bits_per_packet))}"


        assert verbose >= 0 or verbose >= 1 or verbose >= 2 or verbose >= 3, "verbose must be 0, 1, 2 or 3"

        assert dst_port >= 0, "dst_port must be bigger than or equal to 0"
        assert dst_port <= 65535, "dst_port must be smaller than or equal to 65535"

        assert receiver_ip_address != "", "receiver_ip_address must not be empty"





        # create the ip packet
        ip_packet = scapy.all.IP(dst = receiver_ip_address)


        # convert boolean values from string to boolean
        randomize_borders               = randomize_borders               == "True"
        randomize_interval_order        = randomize_interval_order        == "True"
        store_packets_prior_to_sending  = store_packets_prior_to_sending  == "True"
        use_additional_dynamic_shifting = use_additional_dynamic_shifting == "True"

        # set use_additional_dynamic_shifting and bits_per_packet as class variables
        self.use_additional_dynamic_shifting = use_additional_dynamic_shifting
        self.bits_per_packet = bits_per_packet

        # if additional dynamic shifting is used, use a packet counter
        if use_additional_dynamic_shifting:
            self.packet_counter = 0


        binary_message = self.generate_random_binary_message_with_logging(
            log_file_name = log_file_name,
            min_length    = min_length,
            max_length    = max_length
        )

        # initialize the intervals
        if not self.random_seed_and_intervals_set_send:
            self.init_intervals(
                bits_per_packet          = bits_per_packet,
                random_seed              = random_seed,
                sender_receiver_type     = 0,
                randomize_borders        = randomize_borders,
                randomize_interval_order = randomize_interval_order,
                verbose                  = verbose
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

        

        # calculate the number of packets to send
        number_of_packets_to_send = math.ceil(len(binary_message_padded) / bits_per_packet)

        # convert the number of packets to binary (integer_bit_size_to_inform_packet_count bit integer value)
        number_of_packets_to_send_binary = self.convert_integer_to_binary_string(number_of_packets_to_send, integer_bit_size_to_inform_packet_count)

        # apply padding if necessary
        if len(number_of_packets_to_send_binary) % bits_per_packet != 0:
            number_of_packets_to_send_binary_padded = number_of_packets_to_send_binary + "0" * (bits_per_packet - (integer_bit_size_to_inform_packet_count % bits_per_packet))
        else:
            number_of_packets_to_send_binary_padded = number_of_packets_to_send_binary

        if store_packets_prior_to_sending:
            # send packets after creating all of them

            # store the packets to indicate number of packets to send
            packets_to_inform_number_of_packets_to_send = []

            # iterate over the binary number of packets to send and send each bit as a UDP packet
            for i in range(0, len(number_of_packets_to_send_binary_padded), bits_per_packet):
                # get the bits
                bits = number_of_packets_to_send_binary_padded[i:i+bits_per_packet]

                # define the source port number
                src_port = self.get_source_port_encrypted(bits)

                # define the UDP packet
                udp_packet = scapy.all.UDP(sport = src_port, dport = dst_port)

                # add the packet to list
                packets_to_inform_number_of_packets_to_send.append(ip_packet/udp_packet)


            # store packets to send for better timing
            packets_to_send = []

            # iterate over the binary message and send each bit as a UDP packet
            for i in range(0, len(binary_message_padded), bits_per_packet):
                # get the bits
                bits = binary_message_padded[i:i+bits_per_packet]

                # define the source port number
                src_port = self.get_source_port_encrypted(bits)

                # define the UDP packet
                udp_packet = scapy.all.UDP(sport = src_port, dport = dst_port)

                # add the packet to list
                packets_to_send.append(ip_packet/udp_packet)

            # FIRST PLACE I SENT ANY PACKET
            if verbose >= 0:
                timer_start_all_packets = time.perf_counter()

            # first send the packets to inform the number of packets to send
            for current_packet_to_send in packets_to_inform_number_of_packets_to_send:
                # send the packet
                super().send(current_packet_to_send)

                if verbose >= 2:
                    print(f"Sent packet number with source port: {current_packet_to_send[scapy.all.UDP].sport}")

                #time.sleep(sleep_between_packets)


            # sleep for a while to separate the packets
            time.sleep(sleep_between_packet_number_info_and_actual_message)

            # then send the packets to send the message
            for current_packet_to_send in packets_to_send:
                # send the packet
                super().send(current_packet_to_send)

                if verbose >= 2:
                    print(f"Sent with source port: {current_packet_to_send[scapy.all.UDP].sport}")

                #time.sleep(sleep_between_packets)
        else:
            # send packets just after creating them

            # FIRST PLACE I SENT ANY PACKET
            if verbose >= 0:
                timer_start_all_packets = time.perf_counter()
            

            # first send the packets to inform the number of packets to send
            for i in range(0, len(number_of_packets_to_send_binary_padded), bits_per_packet):
                # get the bits
                bits = number_of_packets_to_send_binary_padded[i:i+bits_per_packet]

                # define the source port number
                src_port = self.get_source_port_encrypted(bits)

                # define the UDP packet
                udp_packet = scapy.all.UDP(sport = src_port, dport = dst_port)

                # send the packet
                super().send(ip_packet/udp_packet)

                if verbose >= 2:
                    print(f"Sent packet number with source port: {src_port}")

                time.sleep(sleep_between_packets)
            
            # sleep for a while to separate the packets
            time.sleep(sleep_between_packet_number_info_and_actual_message)

            # then send the packets to send the message
            for i in range(0, len(binary_message_padded), bits_per_packet):
                # get the bits
                bits = binary_message_padded[i:i+bits_per_packet]

                # define the source port number
                src_port = self.get_source_port_encrypted(bits)

                # define the UDP packet
                udp_packet = scapy.all.UDP(sport = src_port, dport = dst_port)

                # send the packet
                super().send(ip_packet/udp_packet)

                if verbose >= 2:
                    print(f"Sent with source port: {src_port}")

                time.sleep(sleep_between_packets)
        

        # AFTER ALL PACKETS ARE SENT
        if verbose >= 0:
            timer_end_all_packets = time.perf_counter()

            seconds_passed = (timer_end_all_packets - timer_start_all_packets)

            print(f"Total time to send all packets: {seconds_passed} seconds")

            # calculate average bits per second
            average_bits_per_second = len(binary_message_padded) / seconds_passed

            print(f"Average bits per second: {average_bits_per_second}")



        
        if verbose >= 2:
            print(f"Sent full message binary: {binary_message}")

            print(f"Sent full message characters: \"", end="")
            
            for i in range(0, len(binary_message), 8):
                print(self.convert_eight_bits_to_character(binary_message[i:i+8]), end="")
            print("\"")


    def receive(
        self,
        bits_per_packet                        : int,
        randomize_borders                      : str = "True",
        randomize_interval_order               : str = "True",
        use_additional_dynamic_shifting        : str = "True",
        cache_type_source_port_value_to_bits   : int = 1,
        random_seed                            : int = 42,
        verbose                                : int = 1,
        integer_bit_size_to_inform_packet_count: int = 32,
        log_file_name                          : str = "Example_UDPTimingInterarrivalChannelReceiver.log",
        dst_port                               : int = 42424,
    ):
        """
        Starts the receiver and waits for the sender to send the message. After receiving the message, decodes the message and logs it to a file.

        Parameters:
        -  bits_per_packet (int): the number of bits to encode in a single packet
        -  Explanation          : The number of bits to encode in a single packet. Larger values increase the capacity of the covert channel, but tightens the intervals.
        -- restrictions         : 1 <= bits_per_packet <= 16

        - randomize_borders (str) (default="True"): whether to randomize the borders of the intervals
        - Explanation                             : If True, the border values of the intervals are randomized. If False, the borders are uniformly distributed.

        - randomize_interval_order (str) (default="True"): whether to randomize the order of the intervals
        - Explanation                                    : If True, the order of the intervals is randomized. If False, the order is kept as it is (form 0 to n-1).

        - use_additional_dynamic_shifting (str) (default="True"): whether to reverse the additional dynamic shifting
        - Explanation                                           : If True, then messages left to right circularly by (self.packet_counter*3 + self.packet_counter**2//3) % (self.bits_per_packet - 1) + 1 bits after decoding from source port values. If False, no shifting is needs to be reversed.

        -  cache_type_source_port_value_to_bits (int) (default=1): the data structure to use for caching the source port value to bits mapping
        -  Explanation                                           : The data structure to use for caching the source port value to bits mapping.
        -- 1                                                     : binary search with O(log(n)) time complexity in terms of number of intervals. Balances memory and initialization time and search time.
        -- 2                                                     : lookup table with O(1) time complexity in terms of number of intervals. Fastest search time,       but requires significant memory and initialization time for large number of intervals.

        - random_seed (int) (default=42): the random seed to use for randomizing the intervals
        - Explanation                   : The random seed to use for randomizing the borders of the intervals and the interval order.

        -  verbose (int) (default=0): the verbosity level
        -- 0                        : no verbosity
        -- 1                        : print initialization time and most important information
        -- 2                        : print all information
        -- 3                        : print all information and the mapping between bits and intervals

        - log_file_name (str) (default="Example_UDPTimingInterarrivalChannelReceiver.log"): the name of the log file to log the received message
        - Explanation                                                                     : The log file of the received message will be stored in this file.

        -  dst_port (int) (default=42424): the destination port to listen for the packets
        -  Explanation                   : The destination port to listen for the packets. (to avoid sniffing wrong packets accidentally)
        -- restrictions                  : 0 <= dst_port <= 65535
        """
        if verbose >= 1:
            # start timer for initial time
            start_time_init = time.time()
        
        # check if the given parameters are valid
        assert bits_per_packet > 0, "bits_per_packet must be bigger than 0"
        assert bits_per_packet <= 16, "bits_per_packet must be smaller than or equal to 16"

        assert randomize_borders == "True" or randomize_borders == "False", "randomize_borders must be either True or False as a string"
        assert randomize_interval_order == "True" or randomize_interval_order == "False", "randomize_interval_order must be either True or False as a string"

        assert verbose >= 0 or verbose >= 1 or verbose >= 2 or verbose >= 3, "verbose must be 0, 1, 2 or 3"

        assert cache_type_source_port_value_to_bits == 1 or cache_type_source_port_value_to_bits == 2, "cache_type_source_port_value_to_bits must be 1 or 2"

        assert dst_port >= 0, "dst_port must be bigger than or equal to 0"
        assert dst_port <= 65535, "dst_port must be smaller than or equal to 65535"



        # convert boolean values from string to boolean
        randomize_borders               = randomize_borders               == "True"
        randomize_interval_order        = randomize_interval_order        == "True"
        use_additional_dynamic_shifting = use_additional_dynamic_shifting == "True"


        # set the dst port, verbose, bits per packet, cache type, use_additional_dynamic_shifting as class variables
        self.dst_port                             = dst_port
        self.verbose                              = verbose
        self.bits_per_packet                      = bits_per_packet
        self.cache_type_source_port_value_to_bits = cache_type_source_port_value_to_bits
        self.use_additional_dynamic_shifting      = use_additional_dynamic_shifting

        # if additional dynamic shifting is used, use a packet counter
        if use_additional_dynamic_shifting:
            self.packet_counter = 0



        # set if interval order is randomized
        self.randomize_interval_order = randomize_interval_order


        # initialize the intervals
        if not self.random_seed_and_intervals_set_receive:
            self.init_intervals(
                bits_per_packet                      = bits_per_packet,
                random_seed                          = random_seed,
                sender_receiver_type                 = 1,
                randomize_borders                    = randomize_borders,
                randomize_interval_order             = randomize_interval_order,
                cache_type_source_port_value_to_bits = cache_type_source_port_value_to_bits,
                verbose                              = verbose
            )

            self.random_seed_and_intervals_set_receive = True

        # receive the packets and decode the message
        message = ""
        bits_actual_message = ""
        bits_buffer_for_packet_count_information = ""

        # calculate the needed packet count to encode a integer
        number_of_packets_to_send = math.ceil(integer_bit_size_to_inform_packet_count / bits_per_packet)

        if verbose >= 1:
            end_time_init = time.time()
            print(f"Initialization time: {(end_time_init - start_time_init) * 1000} ms")
            print("Receiving...")

        # indefinitely wait for "number_of_packets_to_send" packets
        packets_for_number_of_packets_information = scapy.all.sniff(
            count  = number_of_packets_to_send,
            filter = f"udp and dst port {dst_port}"
        )

        if verbose >= 1:
            timer_start_between_packet_info_and_actual_message = time.time()

        if verbose >= 2:
            print(f"Received {number_of_packets_to_send} packets for number of packets information")

        # iterate over the packets to extract the bits
        for current_packet in packets_for_number_of_packets_information:
            # get the source port
            src_port = current_packet[scapy.all.UDP].sport

            # get the bits
            bits = self.get_decrypted_message_from_encrypted_source_port(src_port)

            # add the bits to the buffer
            bits_buffer_for_packet_count_information += bits

            if verbose >= 2:
                print(f"Received packet count information bits: {bits} with source port: {src_port}")

        # clip the bits to the needed length
        bits_buffer_for_packet_count_information = bits_buffer_for_packet_count_information[:integer_bit_size_to_inform_packet_count]

        if verbose >= 2:
            print(f"Received number of packets to receive binary: {bits_buffer_for_packet_count_information}")

        # convert the message to bit integer
        number_of_packets_to_receive = int(bits_buffer_for_packet_count_information, 2)

        if verbose >= 2:
            print(f"Received number of packets to receive: {number_of_packets_to_receive}")
        

        if verbose >= 1:
            timer_end_between_packet_info_and_actual_message = time.time()
            print(f"Time between packet count information and actual message: {(timer_end_between_packet_info_and_actual_message - timer_start_between_packet_info_and_actual_message) * 1000} ms")
        
        # indefinitely wait for "number_of_packets_to_receive" packets
        packets = scapy.all.sniff(
            count = number_of_packets_to_receive,
            filter = f"udp and dst port {dst_port}"
        )



        # iterate over the packets to extract the bits
        for current_packet in packets:
            # get the source port
            src_port = current_packet[scapy.all.UDP].sport
            # get the bits
            bits = self.get_decrypted_message_from_encrypted_source_port(src_port)

            if verbose >= 2:
                print(f"Received bits: {bits} with source port: {src_port}")

            # add the bits to the buffer
            bits_actual_message += bits


        # iterate over the bits and convert them to characters
        for i in range(0, len(bits_actual_message), 8):
            current_character = self.convert_eight_bits_to_character(bits_actual_message[i:i+8])

            if verbose >= 2:
                print(f"Current character: {current_character}")


            # add the character to the message
            message += current_character

            # check if the communication is finished
            if current_character == ".":
                if verbose >= 2:
                    print("\n\nCommunication finished (received \".\")\n\n")
                    break

        
        if verbose >= 2:
            print(f"Received full message binary: {bits_actual_message}")
            print(f"Received full message characters: \"{message}\"")

        self.log_message(message, log_file_name)
        
        

    def convert_integer_to_binary_string(
        self,
        number : int,
        length : int
    ):
        """
        Converts the integer to binary string with the given length
        """
        return bin(number)[2:].zfill(length)

    def init_intervals(
        self,
        bits_per_packet : int,
        random_seed : int,
        sender_receiver_type : int,
        randomize_borders : bool = True,
        randomize_interval_order : bool = True,
        cache_type_source_port_value_to_bits: int = 1,
        verbose : int = 0
    ):
        """
        Initialize the intervals the mapping function between bits to encode and source port value intervals

        Parameters:
        -  bits_per_packet (int): the number of bits to encode in a single packet
        -  Explanation          : The number of bits to encode in a single packet. Larger values increase the capacity of the covert channel, but tightens the intervals.
        -- restrictions         : 1 <= bits_per_packet <= 16

        - random_seed (int): the random seed to use for randomizing the intervals
        - Explanation      : The random seed to use for randomizing the borders of the intervals and the interval order.
        
        -  sender_receiver_type (int): the type of the sender or receiver
        -  Explanation               : Initializes the intervals for the sender, receiver or both
        -- 0                         : sender
        -- 1                         : receiver
        -- 2                         : both

        - randomize_borders (bool) (default=True): whether to randomize the borders of the intervals
        - Explanation                            : If True, the border values of the intervals are randomized. If False, the borders are uniformly distributed.

        - randomize_interval_order (bool) (default=True): whether to randomize the order of the intervals
        - Explanation                                   : If True, the order of the intervals is randomized. If False, the order is kept as it is (form 0 to n-1).

        -  verbose (int) (default=0): the verbosity level
        -- 0                        : no verbosity
        -- 1                        : print initialization time and most important information
        -- 2                        : print all information
        -- 3                        : print all information and the mapping between bits and intervals

        -  cache_type_source_port_value_to_bits (int) (default=1): the data structure to use for caching the source port value to bits mapping
        -- 0                                                     : no caching with O(n) time complexity in terms of number of intervals. Fastest initialization time, requires no additional memory, but slowest search time.
        -- 1                                                     : binary search with O(log(n)) time complexity in terms of number of intervals. Balances memory and initialization time and search time.
        -- 2                                                     : lookup table with O(1) time complexity in terms of number of intervals. Fastest search time, but requires significant memory and initialization time for large number of intervals.
        """

        # check if the given parameters are valid
        assert bits_per_packet > 0, "bits_per_packet must be bigger than 0"
        assert bits_per_packet <= 16, "bits_per_packet must be smaller than or equal to 16"

        assert sender_receiver_type == 0 or sender_receiver_type == 1 or sender_receiver_type == 2, "sender_receiver_type must be 0, 1 or 2"

        assert verbose >= 0 or verbose >= 1 or verbose >= 2 or verbose >= 3, "verbose must be 0, 1, 2 or 3"




        # calculate the number of intervals (2^bits_per_packet)
        number_of_intervals = 2 ** bits_per_packet

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
            src_port_interval_borders = random.sample(range(1, 65536), number_of_intervals - 1)

            # sort the borders
            src_port_interval_borders.sort()

            # add 0 and 65535 as the first and last borders
            src_port_interval_borders.insert(0, 0)
            src_port_interval_borders.append(65535)
        else: # if the borders are not randomized
            # uniformly distribute borders
            src_port_interval_borders = list(range(0, 65536, 65536 // number_of_intervals))

            # add last border
            src_port_interval_borders.append(65535)
            

        

        # define the interval order
        interval_order_normal = range(number_of_intervals)

        # if the interval order needs to be randomized
        if randomize_interval_order:
            # shuffle the interval order to complicate encryption further
            interval_order_randomized = random.sample(interval_order_normal, number_of_intervals)


        if verbose >= 3:
            print(f"Number of intervals: {number_of_intervals}")
            if randomize_interval_order:
                print(f"Interval order: \n{interval_order_randomized}\n")
            print(f"Interval borders: \n{src_port_interval_borders}\n")


        # check if the sender or receiver is initializing the intervals
        if sender_receiver_type == 0 or sender_receiver_type == 2: # sender mode or both mode 
            # fill the hashmap which will be used to obtain the source port value interval using encoded bits

            # create a hashmap (key: bits as string, value: interval as a tuple of 2 integers)
            self.bits_to_source_port_value_interval = dict()

            if verbose >= 3:
                print("bits to source port value interval mapping:")

            for i in interval_order_normal:
                # if randomize_interval_order is true, use the randomized interval order
                if randomize_interval_order:
                    border_index = interval_order_randomized[i]
                else:
                    border_index = i
                

                if verbose >= 3:
                    print(f"{i}: {self.convert_integer_to_binary_string(i, bits_per_packet)} ---> [{src_port_interval_borders[border_index]}, {src_port_interval_borders[border_index+1]})")
                
                self.bits_to_source_port_value_interval[self.convert_integer_to_binary_string(i, bits_per_packet)] = (src_port_interval_borders[border_index], src_port_interval_borders[border_index+1])


        if sender_receiver_type == 1 or sender_receiver_type == 2: # receiver mode or both mode

            if cache_type_source_port_value_to_bits == 0: # no caching
                # do nothing. Implementation will be done in the receive function
                pass

            elif cache_type_source_port_value_to_bits == 1: # binary search
                # we will use the interval_order_normal (not randomized) for binary search
                self.nonrandomized_interval_border_values = src_port_interval_borders[:-1]

                # if the interval order is randomized, it is also needed to be stored
                if randomize_interval_order:
                    self.interval_order_randomized = interval_order_randomized

                # rest of the binary search implementation should be done in the receive function

            elif cache_type_source_port_value_to_bits == 2: # lookup table
                # create a lookup table (index: source port value, value: bits as string)
                self.source_port_value_to_bits = []

                if verbose >= 3:
                    print("source port value to bits mapping (samples of every 1000th source port value):")

                unrandomized_interval = 0
                # here I pre-computed all the possible source port values to avoid O(n) search for each packet in the transmission time.
                for i in range(0, 65535):
                    # find the interval of the source port value
                    interval = 0

                    # stop the search when the interval is found
                    if i >= src_port_interval_borders[unrandomized_interval+1]:
                        unrandomized_interval += 1
                    
                    
                    # if interval order is randomized, find the original interval
                    if randomize_interval_order:
                        interval = interval_order_randomized.index(unrandomized_interval)
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
        bits : str
    ):
        """
        Get the encrypted source port value from the bits

        Parameters:
        -  bits (str)                     : the bit to encrypt
        -- examples for 5 bits per packet: "00000", "00001", "00010", "00011", ..., "11111"

        Returns:
        - int: the encrypted source port value

        --- WARNING: this function has to be called after the intervals are initialized with the sender mode ---
        """

        # if additional dynamic shifting is used, shift the bits to right circularly by (self.packet_counter*3 + self.packet_counter**2//3) % (self.bits_per_packet - 1) + 1 bits
        if self.use_additional_dynamic_shifting:
            # calculate the shift amount
            shift_amount = (self.packet_counter*3 + self.packet_counter**2//3) % (self.bits_per_packet - 1) + 1

            # shift the bits to right circularly
            bits = bits[-shift_amount:] + bits[:-shift_amount]


            # increase the packet counter
            self.packet_counter = (self.packet_counter + 1) % (self.bits_per_packet*7 - 1)

        # get the current interval:
        current_interval = self.bits_to_source_port_value_interval[bits]

        # return a random value from the interval (including the lower bound, excluding the upper bound)
        return random.randint(current_interval[0], current_interval[1]-1)
    
    def get_decrypted_message_from_encrypted_source_port(
        self,
        src_port : int
    ):
        """
        Get the decrypted message from the encrypted source port value

        Parameters:
        - src_port (int): the source port value to decrypt
        - Explanation   : The source port value to decrypt

        --- WARNING: this function has to be called after the intervals are initialized with the receiver mode ---
        """

        if self.cache_type_source_port_value_to_bits == 1: # binary search
            # we will apply binary search on the sorted interval border list to find the interval index.

            left_index = 0
            right_index = len(self.nonrandomized_interval_border_values) - 1


            while left_index <= right_index:
                # get the middle index
                middle_index = left_index + (right_index - left_index) // 2

                # get the middle index border value
                middle_value = self.nonrandomized_interval_border_values[middle_index]

                
                # compare middle value with the source port value to find the largest border value smaller or equal to source port
                if middle_value <= src_port:
                    left_index = middle_index + 1
                else:
                    right_index = middle_index - 1

            interval_index = left_index - 1
                    

            # we have the index of interval where current source port value belongs. Now, check if interval order is randomized
            if self.randomize_interval_order:
                # find the randomized correspoding interval
                randomized_corresponding_interval = self.interval_order_randomized.index(interval_index)

                # convert this value to binary to find encoded bits
                binary_bits = self.convert_integer_to_binary_string(randomized_corresponding_interval, self.bits_per_packet)
            else:
                # convert this value to binary to find encoded bits directly
                binary_bits = self.convert_integer_to_binary_string(interval_index, self.bits_per_packet)
            
            # if additional dynamic shifting is used, shift the bits to left circularly by (self.packet_counter*3 + self.packet_counter**2//3) % (self.bits_per_packet - 1) + 1 bits
            if self.use_additional_dynamic_shifting:
                # calculate the shift amount
                shift_amount = (self.packet_counter*3 + self.packet_counter**2//3) % (self.bits_per_packet - 1) + 1

                # shift the bits to left circularly
                binary_bits = binary_bits[shift_amount:] + binary_bits[:shift_amount]

                # increase the packet counter
                self.packet_counter = (self.packet_counter + 1) % (self.bits_per_packet*7 - 1)

            return binary_bits



        elif self.cache_type_source_port_value_to_bits == 2: # lookup table
            # return the bits corresponding to the source port value in O(1) time complexity
            return self.source_port_value_to_bits[src_port]
        

