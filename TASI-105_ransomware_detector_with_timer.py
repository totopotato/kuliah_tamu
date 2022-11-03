import pickle
import sys
import os
import time
import subprocess
import pefile
import numpy as np

ida_path = os.path.join(os.environ['PROGRAMFILES'], "IDA 7.2", "idat.exe")
pe_path = str(sys.argv[1]).replace('\\','\\\\')
ida_script_path = "..\\ida_script.py"
model_path = "..\\ransomware_dtmodel_11fitur.pkl"
windows_crypto_api_path = "..\\windows_crypto_api.txt"
windows_file_operation_api_path = "..\\windows_file_operation_api.txt"
windows_internet_connection_api_path = "..\\windows_internet_connection_api.txt"

#Feature Parameter
known_packer = ['.themida', '.upx', '.UPX0', '.UPX1', '.UPX2', '.UPX', '']
traverse_api = ['FindFirstFile', 'FindClose', 'FindFirstFileW', 'FindFirstFileA', 'FindFirstFileAx', 'FindNextFile', 'FindNextFileW', 'FindNextFileA', 'FindNextFileAx', 'FindNextFileEx', 'CreateFile', 'CreateFileA', 'CreateFileW', 'CreateFileAx', 'DeleteFile', 'DeleteFileA', 'DeleteFileW', 'DeleteFileAx']
anti_debug_api = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent']
common_section = ['.bss','.BSS','.code','.CRT','.data','.DATA','.data','.debug','.drectve ','.didat','.didata','.edata','.export','.idata','.impdata','.import','.itext','.ndata','.pdata','.rdata','.reloc','.rsrc','.sbss','.script','.stab','.text','.textbss','.tls','.udata','.INIT','.sdata','.shared']
executable_flags = ['1', '3', '5', '7']
#Read File Operation API list from file
read_windows_file_operation_api = open(windows_file_operation_api_path, "r")
read_windows_file_operation_api_output = read_windows_file_operation_api.read()
windows_file_operation_api = read_windows_file_operation_api_output.split('\n')
read_windows_file_operation_api.close()
#Read Windows Crypto API list from file
read_windows_crypto_api = open(windows_crypto_api_path, "r")
read_windows_crypto_api_output = read_windows_crypto_api.read()
windows_crypto_api = read_windows_crypto_api_output.split('\n')
read_windows_crypto_api.close()
#Read Windows Internet Connection API list from file
read_windows_internet_connection_api = open(windows_internet_connection_api_path, "r")
read_windows_internet_connection_api_output = read_windows_internet_connection_api.read()
windows_internet_connection_api = read_windows_internet_connection_api_output.split('\n')
read_windows_internet_connection_api.close()

#Global Variable
sections = []
section_size = []
api_calls = []
feature = []
segments = []
segments_attribute = []

#Feature Variable
is_text_section_available = 0
additional_section = 0
is_any_exec_section_besides_text = 0
traverse_operation = 0
encryption_using_windows_crypto_api = 0
encryption_using_custom_function = 0
file_operation = 0
internet_connection = 0
known_packer_section = 0
# relative_size_of_additional_section = 0
# superfluous_intruction_in_executable_section = 0
# encoding_decoding_stub = 0
is_any_environtment_fingerprinting = 0
is_iat_available = 0

start = time.time()

pe = pefile.PE(pe_path, fast_load=True)

#Parse PE API Call List from Import Address Table
pe.parse_data_directories()
try:
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            api_calls.append(imp.name.decode('UTF-8'))
    is_iat_available = 1
except:
    api_calls = []
    is_iat_available = 0
run_ida = subprocess.call([ida_path, "-B", "-S"+ida_script_path, pe_path])
if(run_ida == 1):
    print("Error : File cannot be parsed, different file format or file is corrupted")
else:
    # Retrieving IDA Python script output
    runtime_call_output = open('output_runtime_call.txt', encoding="utf8")
    runtime_call = runtime_call_output.read().split('], [')
    runtime_call[0] = runtime_call[0][2:]
    runtime_call[len(runtime_call)-1] = runtime_call[len(runtime_call)-1][:-2]

    segment_output = open('output_segment.txt', encoding="utf8")
    segment = segment_output.read().split(',')

    encryption_using_custom_function_output = open('output_encryption_using_custom_function.txt', encoding="utf8")
    encryption_using_custom_function = encryption_using_custom_function_output.read()
    if encryption_using_custom_function == '[]':
        encryption_using_custom_function = 0
    else:
        encryption_using_custom_function = 1

    # Appending the output into variable
    for i in range(len(runtime_call)):
        runtime_call[i] = runtime_call[i][24:]

    # Appending the output into variable
    for i in range(len(segment)):
        if(i % 2 == 0):
            segments.append(segment[i])
        else:
            segments_attribute.append(segment[i])

    # Pre-processing the ouput
    #removing punctuation from output
    punctuations = ''' !,()-[]{}:'"\<>./?@#$%^&*=~–'''
    segment_output_punctuations = ''' !,()-[]{}:'"\<>/?@#$%^&*=~–'''
    runtime_call = [''.join(c for c in s if c not in punctuations) for s in runtime_call]
    segments = [''.join(c for c in s if c not in segment_output_punctuations) for s in segments]
    segments_attribute = [''.join(c for c in s if c not in segment_output_punctuations) for s in segments_attribute]

    #removing null value and duplicate API Call from output
    runtime_api_calls = list(filter(None, runtime_call))
    runtime_api_calls = list(dict.fromkeys(runtime_api_calls))

    #Feature Extraction
    # Extracting Feature 1 : is_text_section_available
    if any(".text" in i for i in segments):
        is_text_section_available = 1
    else:
        is_text_section_available = 0

    feature.append(is_text_section_available)

    # Extracting Feature 2 : additional_section
    for section in segments:
        if section not in common_section:
            additional_section = 1
            break

    feature.append(additional_section)

    # Extracting Feature 3 : is_any_exec_section_besides_text
    for i in range(len(segments)):
        if ((segments[i] != '.text') & (segments_attribute[i] in executable_flags)):
            is_any_exec_section_besides_text = 1
            break

    feature.append(is_any_exec_section_besides_text)

    # Extracting Feature 4 : traverse_operation
    for api in api_calls:
        if api in traverse_api:
            traverse_operation = 1
            break

    feature.append(traverse_operation)

    # Extracting Feature 5 : encryption_using_windows_crypto_api
    for api in api_calls:
        if api in windows_crypto_api:
            encryption_using_windows_crypto_api = 1
            break

    feature.append(encryption_using_windows_crypto_api)

    # Extracting Feature 6 : file_operation
    for api in api_calls:
        if api in windows_file_operation_api:
            file_operation = 1
            break

    feature.append(file_operation)

    # Extracting Feature 7 : internet_connection
    for api in api_calls:
        if api in windows_internet_connection_api:
            internet_connection = 1
            break

    feature.append(internet_connection)

    # Extracting Feature 8 : known_packer_section
    for section in sections:
        if section in known_packer:
            known_packer_section = 1
            break

    feature.append(known_packer_section)

    # Extracting Feature 9 : is_any_environtment_fingerprinting
    for api in api_calls:
        if api in anti_debug_api:
            is_any_environtment_fingerprinting = 1
            break

    feature.append(is_any_environtment_fingerprinting)

    # Extracting Feature 10 : encryption_using_custom_function
    feature.append(encryption_using_custom_function)

    # Extracting Feature 11 : is_iat_available
    feature.append(is_iat_available)

    end_parsing = time.time()
    
    model = pickle.load(open(model_path, 'rb'))
    feature = np.array(feature)
    result = model.predict(feature.reshape(1,-1))
    if result == "ransomware":
        print("Your File is Ransomware")
    elif result == "benign":
        print("Your File is Goodware")

    end_detection = time.time()

    parsing_time = end_parsing - start
    detection_time = end_detection - end_parsing

    print("Parsing time needed is : ", parsing_time, "s")
    print("Detection time : ", detection_time, "s")