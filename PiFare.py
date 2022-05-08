from multiprocessing import AuthenticationError
from tabulate import tabulate
from colorama import init, Fore
import RPi.GPIO as GPIO
import MFRC522
import json
import os


init(autoreset=True) # colorama autoreset
GPIO.setwarnings(False) # hide GPIO warnings


MIFARE1K_BLOCKS = list(range(64))  # 64 blocks in total
MIFARE1K_BLOCKS_PER_SECTOR = 4     # 4 blocks/sector (each block is 16 bytes)
MIFARE1K_SECTORS = list(range(16)) # 16 sectors

MIFARE1K_KEYS_LENGTH = 12 #KeyA and KeyB are 6 bytes each (12 chars in string: AABBCCDDEEFF)

WORKING_DIR = os.path.abspath(os.getcwd())
BRUTEFORCE_DICTIONARY = "./dicts/default_keys.txt" # LoDelOtroDia.txt extended-std.keys.txt
JSON_DATA_TEMPLATE = f"{os.path.abspath(os.getcwd())}/data/mifareCardTemplate.json" # Tempalte to store data for new cards



BANNER = \
Fore.CYAN + '''

  _____  _____ _______ _______  ______ _______
 |_____]   |   |______ |_____| |_____/ |______
 |       __|__ |       |     | |    \_ |______
                                              

                                                                                                         
RC522 RFID interface + Raspberry Pi                                                                                                       

\t\t\t\t\t\tv0.0.1
'''


#Class to manage the info a card can have
class MifareCard():
    '''
    This class contains all the necessary methods to read a mifare classic 1k card and to perform 
    brute force attacks with dictionaries in case the corresponding keys are not known.
    '''

    # Constructor
    def __init__(self) -> None:
        self.rc522Handler = Rc522Handler()       
        
        self.cardUID = self.ReadUID()
        self.PrintUID()

        self.cardFile = self.GetCardFileNameIfDataExistsOrCreateNewOne()
        self.cardDataInJSON = self.GetDataFromJson()
        self.isCardPartialAccesible, self.isCardAccesible = self.CheckIfKeysExist() # isCardPartialAccesible = KeysA or KeysB found (not both) | isCardAccesible = all keys found


    # Print the UID of the card in a fancy way
    def PrintUID(self) -> None: 
        print(tabulate([["UID"], [self.cardUID]], tablefmt="fancy_grid"))


    # Read the UID from the card
    def ReadUID(self) -> str:
        return self.rc522Handler.ReadUID()


    # Print the data read from the card (64 blocks divided into 16 sectors) in a fancy way
    def PrintDataColored(self) -> None: 
        
        for sector in MIFARE1K_SECTORS: 
            stringToPrint = ""

            startBlock = sector * MIFARE1K_BLOCKS_PER_SECTOR
            endblock = startBlock + MIFARE1K_BLOCKS_PER_SECTOR

            blocksInSector = list(range(startBlock, endblock)) # For example, the blocks from sector 14 (starting in sector 0) are block 56, 57, 58 and 59 (starting in block 0) 
                                                               # Blocks from sector 16 are 60, 61, 62 and 63 (last block of the Mifare 1k) 

            for block in blocksInSector: 
                blockData = self.cardDataInJSON["blocks"][f"{block}"] # Read block data from jsonfile

                if block == 0:
                    stringToPrint += Fore.MAGENTA + blockData # Block 0 represents the UID and manufacturer data

                elif (block+1) %4  == 0: #In the 4th block of each sector the KeyA and KeyB are located (and also de access conditions for the sector) 
                    
                    keyA = self.cardDataInJSON["SectorKeys"][f"{sector}"]["KeyA"].upper()
                    if keyA != "": keyA = ' '.join(keyA[i:i+2] for i in range(0, len(keyA), 2)) + " " # Adjust string for fancy printing (KeyA)
                    else: keyA = "-- -- -- -- -- --"

                    AccessConditions = Fore.YELLOW + blockData[18:30] 

                    keyB = self.cardDataInJSON["SectorKeys"][f"{sector}"]["KeyB"].upper()
                    if keyB != "": keyB = ' '.join(keyB[i:i+2] for i in range(0, len(keyB), 2)) # Adjust string for fancy printing (KeyB)
                    else: keyB = "-- -- -- -- -- --"

                    stringToPrint +=  Fore.CYAN + keyA + Fore.YELLOW + AccessConditions + Fore.CYAN + keyB 
                
                else: 
                    stringToPrint += Fore.WHITE + blockData 
                
                stringToPrint += "\n"

            print(tabulate([[f"Sector {sector}"], [stringToPrint]], tablefmt="pretty"))


    # Check if the card is already known and is saved in some json file or if it is a new card (so a new file has to be created)
    def GetCardFileNameIfDataExistsOrCreateNewOne(self) -> str: 
        jsonFile = f"./data/{self.cardUID}.json"

        if os.path.isfile(jsonFile): # If a json file exists just return the file name
            print(Fore.GREEN + f"> UID already saved in file {jsonFile}, restoring configuration for this card...\n")    
        
        else: # If not, create a new json file and add the UID to that
            print(Fore.YELLOW + f"> New UID detected. Creating save file in: {jsonFile}\n")

            with open(JSON_DATA_TEMPLATE, 'r') as template: # If there is no data create a new file from the template
                templateData = json.load(template)
            
            templateData["Card"]["UID"] = self.cardUID # Populate UID

            with open(jsonFile, 'w') as newCardFile: 
                newCardFile.write(json.dumps(templateData, indent=4))

        return jsonFile  


    # Read all the blocks in the card with the KeysA (usually the ones for reading)
    def ReadAllBlocksWithKeysA(self) -> None: 
        print(Fore.WHITE + "\n> Reading card....")

        if self.isCardAccesible or self.isCardPartialAccesible: 
            for sector in MIFARE1K_SECTORS: 
                # Reading with Key A
                sectorKeyA = self.cardDataInJSON["SectorKeys"][f"{sector}"]["KeyA"]
                sectorkeyABytes = bytes(bytearray.fromhex(sectorKeyA)) #Convert keys from the dictionary to an array of bytes
                
                blocksBySector = list(range((sector * MIFARE1K_BLOCKS_PER_SECTOR), (sector * MIFARE1K_BLOCKS_PER_SECTOR) + MIFARE1K_BLOCKS_PER_SECTOR))

                dataRead = self.rc522Handler.ReadBlocks(blocksBySector, sectorkeyABytes, "KeyA")

                if dataRead != "":
                    for blockNumber, blockData in enumerate(dataRead): #Convert bytes to hexadecimal and add 0 to the left if is just 1 char
                        bytesInHex = []
                        blockNumber = blockNumber + (sector * MIFARE1K_BLOCKS_PER_SECTOR) #Global block number

                        for byte in blockData: # This is for having all bytes in 2 chars format, for example if a byte is read as "0" or "5" it turns it into "00" or "05"
                            if len(format(byte, 'x')) == 1:
                                bytesInHex.append("0" + format(byte, 'x').upper())
                            else: 
                                bytesInHex.append(format(byte, 'x').upper())  
    
                        self.cardDataInJSON["blocks"][f"{blockNumber}"] = " ".join(bytesInHex)

            self.saveJsonDataToFile()
        
        else: 
            print(Fore.RED + "> There are no keys so is not possible to read the blocks....")


    # Check if there are keys already found for the card or if you want to try a bruteforce attack with dictionary
    def CheckIfKeysExist(self) -> bool:
        isFullAccesible = False # We have all KeysA and all KeysB
        isPartialAccesible = False # We have or KeysA or KeysB but not both

        sectorsWithkeysANotFound = []
        sectorsWithkeysBNotFound = []

        for sector in MIFARE1K_SECTORS: # Going through the sectors and check whether the keys already exist. If not, ask to bruteforcing them
            sectorKeyA = self.cardDataInJSON["SectorKeys"][f"{sector}"]["KeyA"]
            sectorKeyB = self.cardDataInJSON["SectorKeys"][f"{sector}"]["KeyB"]

            if sectorKeyA == "":
                sectorsWithkeysANotFound.append(sector) # Remaining KeysA to be found

            if sectorKeyB == "":
                sectorsWithkeysBNotFound.append(sector) # Remaining KeysB to be found

        if len(sectorsWithkeysANotFound) != 0:
            option = input(Fore.RED + f"> Keys A not found for sectors: {sectorsWithkeysANotFound}. Do you want to bruteforce them? [y/n] ")
            
            if option == "y":
                sectorsFound = self.BruteforceKeys(sectorsWithkeysANotFound, "KeyA")
                [sectorsWithkeysANotFound.remove(sectorFound) for sectorFound in sectorsFound] # Delete found keys from array with not found keys

        if len(sectorsWithkeysANotFound) == 0: # All KeysA found
            print(Fore.GREEN + f"> All Keys A already known")
            isPartialAccesible = True

        if len(sectorsWithkeysBNotFound) != 0:
            option = input(Fore.RED + f"> Keys B not found for sectors: {sectorsWithkeysBNotFound}. Do you want to bruteforce them? [y/n] ")
            
            if option == "y":
                sectorsFound = self.BruteforceKeys(sectorsWithkeysBNotFound, "KeyB")
                [sectorsWithkeysBNotFound.remove(sectorFound) for sectorFound in sectorsFound] # Delete found keys from array with not found keys
        
        if len(sectorsWithkeysBNotFound) == 0: # All KeysB found
            print(Fore.GREEN + f"> All Keys B already known")
            isPartialAccesible = True

        if len(sectorsWithkeysANotFound) == 0 and len(sectorsWithkeysBNotFound) == 0: 
            isFullAccesible = True
        
        return isPartialAccesible, isFullAccesible


    # Bruteforcing keys using a dictionary to trying to read the sectors
    def BruteforceKeys(self, sectorsToBruteforce: list, keyAorB: str = "KeyA") -> bool: 
        keysFound = []

        for sector in sectorsToBruteforce: 
            keyBlock = [(sector * MIFARE1K_BLOCKS_PER_SECTOR) + MIFARE1K_BLOCKS_PER_SECTOR-1] #Calculate global block number from sector 

            try: 
                key = self.BruteForceBlocks(BRUTEFORCE_DICTIONARY, keyBlock, keyAorB)[0]  # Bruteforce sector blocks
                keysFound.append(sector)

            except: 
                key = ""                

            self.cardDataInJSON["SectorKeys"][f"{sector}"][f"{keyAorB}"] = key
        
        self.saveJsonDataToFile()
        return keysFound


    # Save data from MifareCard object to a file
    def saveJsonDataToFile(self):
        with open(self.cardFile, 'w') as cardJSONFile: 
            cardJSONFile.write(json.dumps(self.cardDataInJSON, indent=4))


    # Read card data from JSON file
    def GetDataFromJson(self) -> json: 
        with open(self.cardFile, 'r') as dataFile: 
            data = json.load(dataFile)
        
        return data


    # Bruteforcing block reading with a dictionary
    def BruteForceBlocks(self, dictionary: dict, blocksToBruteForce: list = MIFARE1K_BLOCKS, keyAorB: str = "KeyA") -> list:
        foundKeys = []

        with open(dictionary) as file: # Open dictionary
            keys = file.readlines()

        for block in blocksToBruteForce: 
            print(Fore.YELLOW + f"> [i] - Bruteforcing sector {int(block/MIFARE1K_BLOCKS_PER_SECTOR)} - block {block}") 

            for index, keyString in enumerate(keys): 
                try:
                    keyString = keyString[:MIFARE1K_KEYS_LENGTH]
                    keyBytes = bytes(bytearray.fromhex(keyString)) #Convert keys from the dictionary to an array of bytes

                    blockRead = self.rc522Handler.ReadBlocks([block], keyBytes, keyAorB) # Trying to read block with specified key

                    if blockRead != "": # Sucessfull key
                        print(Fore.GREEN + f"> [✓] - KEY FOUND: {keyString}")
                        foundKeys.append(keyString.upper())
                        break
                    
                    else: #Bad key
                        if index == len(keys)-1:
                            print(Fore.RED + f"> [X] - Unable to find any key from the dictionary for this block")
                        
                        else: 
                            print(f"> [i] - Attempt: {keyString}", end="\r")
                
                except KeyboardInterrupt:
                    exit()

                except Exception as err: 
                    pass
            
            print()
        return foundKeys
        

# Class to hanlde the communication with the RFID Reader
class Rc522Handler(): 

    def __init__(self) -> None:
        self.mifareReader = MFRC522.MFRC522()
        pass

    
    # Read UID from card
    def ReadUID(self) -> str:
        uid = ""
        while True: 
            # Scan for cards
            (status,TagType) = self.mifareReader.MFRC522_Request(self.mifareReader.PICC_REQIDL)

            # Get the UID of the card
            (status,uidRead) = self.mifareReader.MFRC522_Anticoll()

            # If we have the UID, continue
            if status == self.mifareReader.MI_OK:
                for byte in uidRead: 
                    uid +=  format(byte, 'x').upper()

                return uid
            
    # Read blocks
    def ReadBlocks(self, blocks: list = MIFARE1K_BLOCKS, keyValue: list = [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF], keyAorB: str = "KeyA"): 
        blocksDumped = []
        keyUsed = self.mifareReader.PICC_AUTHENT1A

        if keyAorB == "KeyB": 
            keyUsed = self.mifareReader.PICC_AUTHENT1B

        try:
            while True: 
                # Scan for cards
                (status,TagType) = self.mifareReader.MFRC522_Request(self.mifareReader.PICC_REQIDL)

                # Get the UID of the card
                (status,uidRead) = self.mifareReader.MFRC522_Anticoll()
             
                # If we have the UID, continue
                if status == self.mifareReader.MI_OK:

                    # Select card
                    self.mifareReader.MFRC522_SelectTag(uidRead)
                    
                    for block in blocks:
                        # Check if authenticated (Correct Key)
                        status = self.mifareReader.MFRC522_Auth(keyUsed, block, keyValue, uidRead)                        
                        
                        if status == self.mifareReader.MI_OK:
                            blocksDumped.append(self.mifareReader.MFRC522_Read(int(block)))

                        else:
                            raise AuthenticationError
                
                    # Stop
                    self.mifareReader.MFRC522_StopCrypto1()  
                    return blocksDumped

        except AuthenticationError as err:
            return ""



if __name__ == "__main__":
    
    print(BANNER)
    print("> Please put the card in the reader.....\n")

    try: 
        card = MifareCard()  
        card.ReadAllBlocksWithKeysA()
        card.PrintDataColored()

    except KeyboardInterrupt: 
        print(Fore.CYAN + "\n\n> Closing program.... Se you soon ❤️️")

    except Exception as error: 
        print(Fore.RED + "> Something went wrong...")
        print(error)

    GPIO.cleanup()