# Covert Storage Channel that exploits Protocol Field Manipulation using Source Port field in UDP


## Description
This project is prepared for Middle East Technical University (METU) CENG 435 "Data Communications and Networking" course homework.

Main goal is to communicate with a covert channel. Covert channels use a "hidden" communication mechanism to transfer information. Instead of message payload, where the messages normally belong to, covert channels use other fields of the protocol headers or some other techniques such as timing, packet counts in burst, etc. to transfer information. In this project, the covert channel is implemented using the source port field of the UDP protocol, which is a 16-bit field.


## How to run?

Covert channel is implemented using Python programming language, but it is not necessary to install a python environment manually to run the program since a docker image is provided. To install docker, [look at the official docker page here.](https://docs.docker.com/get-docker/)

To start sender and receiver containers:
```sh
docker compose up -d
```

After composing the containers up, open two separate terminals and attach to the sender and receiver containers respectively:
```sh
docker exec -it sender bash
```

```sh
docker exec -it receiver bash
```

You will be in your Ubuntu 22.04 Docker instances (python3.10.12 and scapy installed) with static IP addresses defined in the docker-compose.yml file. (sender: 172.18.0.2, receiver: 172.18.0.3 by default)

Now, you can adjust the function parameters is the config.json file. WARNING: See the [Configuration Restrictions](#configuration-restrictions) section before changing the parameters, as changing some parameters may cause the program to not work properly or not work at all.

After that, you can run the sender and receiver scripts in the sender and receiver containers respectively. First, run the sender script in the sender container:

```sh
make send
```

Then, run the receiver script in the receiver container:
```sh
make receive
```

After everything is done, you can stop the sender and receiver containers.


To stop sender and receiver containers:
```sh
docker compose down
```


## Configuration Restrictions!

First of all, the following parameters must be same in both sender and receiver functions:
"bits_per_packet"\
"randomize_borders"\
"randomize_interval_order"\
"use_additional_dynamic_shifting"\
"dst_port"\
"random_seed"\
"verbose"

Parameter by parameter restrictions/explanations:

Common parameters:

* bits_per_packet: <br> * Restriction: This parameter must be between 1 and 16 inclusively. <br> * Explanation: The higher the bits_per_packet, the higher the data rate through covert channel. When 16 bits are used in a packet, a one to one encryption is achieved between the message and the used source port value.

* randomize_borders: <br> * Restriction: This parameter must be a string that is either "True" or "False". <br> * Explanation: If it is set to "True", the sender and receiver will randomize the borders of the source port field. If it is set to "False", the sender and receiver will use the homogeneously distributed borders between 0 and 65535.

* randomize_interval_order : <br> * Restriction: This parameter must be a string that is either "True" or "False". <br> * Explanation: If it is set to "True", the sender and receiver will randomize the intervals to map the bits to the source port field.

* use_additional_dynamic_shifting : <br> * Restriction: This parameter must be a string that is either "True" or "False". <br> * Explanation: If it is set to "True", the sender and receiver will use additional dynamic shifting to map bits to bits additional to other mapping techniques. Its shifting value changes with a function of the packet's index.

* dst_port : <br> * Restriction: This parameter must be an integer between 0 and 65535 inclusively. <br> * Explanation: This parameter is used to filter the packets while sniffing.

* random_seed : <br> * Restriction: This parameter must be a positive integer. <br> * Explanation: This parameter is used to seed the random number generator.

* verbose : <br> * Restriction: This parameter must be either 0, 1, 2 or 3. <br> * Explanation: 0 is for no verbosity. 1 is for printing initialization time and most important information. 2 is for printing all information. 3 is for printing all information and the mapping between bits and intervals

* log_file_name : <br> * Restriction: Any string. <br> * Explanation: This parameter is used to determine the name of the log file. The log file is created in the sender and receiver functions to check if messages are sent and received correctly, using ```make compare``` command.


Only receiver parameters:

* cache_type_source_port_value_to_bits : <br> * Restriction: This parameter must be either 1 or 2. <br> * Explanation: If it is set to 1, caches only the border values. Then, it uses binary search to find the corresponding bits for a source port value. If it is set to 2, it precalculates the mapping between the source port values and the bits for each 65536 source port value. Then, it uses the precalculated mapping to find the corresponding bits for a source port value. DO NOT recommended to use 2 with bits_per_packet > 13.


Only sender parameters:

* sleep_between_packets: <br> * Restriction: Any positive floating value. In the current implementation, sleep_between_packets can even be 0 since asynchronous sniffing is used with multiple threads in receiver. However, you can set it to a small value to guarantee the packets loss is not occurred. <br> * Explanation: This parameter is used to determine the sleep time between sending packets in the sender.

* store_packets_prior_to_sending : <br> * Restriction: This parameter is a string that is either "True" or "False". <br> * Explanation: If it is set to "True", the sender will store the packets in a list before sending them to save a small amount of time in the sending process. If it is set to "False", the sender will not store the packets in a list before sending them, and creates them just before sending each.

* max_length : <br> * Restriction: Any positive integer. However, too large values causes significant waiting for even creating the binary message string to send and uses too much memory. <br> * Explanation: Maximum length of the randomly generater message that can be sent to test the covert channel.

* min_length : <br> * Restriction: Any positive integer smaller than or equal to the max_length <br> * Explanation: Minimum length of the randomly generater message that can be sent to test the covert channel. 

* receiver_ip_address : <br> * Restriction: The IP address of the receiver. <br> * Explanation: The IP address of the receiver to send the packets.


## Implementation Details

This covert channel implementation uses the 16-bit source port field of UDP header to convey messages. Implementation supports to send all bit counts from 1 to 16 per packet.

Additional to the covert channel secureness, this implementation also contains 3 layers of protection to prevent decryption of the message by an unauthorized user by mapping the bits to the source port field using different techniques.

Let the bit count per packet be 3. Algorithm first creates $2^3 = 8$ intervals between 0 and 65535.

Security technique 1: Randomizing the borders of the intervals. Without this future, the intervals will be homogeneously distributed between 0 and 65535, followingly [(0, 8191), (8192, 16383), (16384, 24575), (24576, 32767), (32768, 40959), (40960, 49151), (49152, 57343), (57344, 65535)]. However, with this feature, the borders of the intervals are randomized, which also means interval ranges are also randomized.

Security technique 2: Randomizing the interval order. After the intervals are created, the bits should be assigned to these intervals. Without this feature, the bits will be assigned to the intervals in the same order as the bits are, such as:\
"000" --> (0, 8191)\
"001" --> (8192, 16383)\
"010" --> (16384, 24575)\
"011" --> (24576, 32767)\
"100" --> (32768, 40959)\
"101" --> (40960, 49151)\
"110" --> (49152, 57343)\
"111" --> (57344, 65535)\
However, with this feature, these mappings are randomized, making the covert channel more secure.

Security technique 3: Using additional dynamic shifting. This feature is used to shift bits to be decoded prior to the interval assignement. To make it even more secure, the shifting value is calculated using a custom function of the packet's index, making it mostly different for each packet. Function is defined as:\
$((packet\_index*3 + packet\_index^2//3) \% (bits\_per\_packet - 1)) + 1$


Sender parses the binary message to n bit chunks, encodes them to the source port field values optionally and suggestedly by using techniques mentioned above, and sends them to the receiver. 

Receiver sniffs UDP packet with the given destination port, decodes the source port field values to the binary message, inverts the techniques used in the sender, and process the binary message to characters. After receiving the "." character, receiver stops the sniffing and logs the message.