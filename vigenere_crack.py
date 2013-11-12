"""
    Vigenere Cipher Crack
    By: Johan Hägg
    2011-03-31
    Using Python v3.2, should work for v3.1 aswell.
    Last Updated 2011-04-04
"""

# Needed to check version
import sys
# Needed to calculate time taken
import time
from string import maketrans

# English letter frequencies a-z, taken from:
# http://en.wikipedia.org/wiki/Letter_frequency
ENGLISH_LETTER_FREQUENCIES = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.996, 0.153,
                             0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
                             2.758, 0.978, 2.360, 0.150, 1.974, 0.074]
NUMBER_OF_LETTERS_IN_ENGLISH_ALPHABET = 26
ASCII_OFFSET = 97

"""
    Calculates the coincidence rate of a text.

    text: String to calculate coincidence rates of.

    returns: The coincidence rate of text.
"""
def coincidence_rate(text):
    kr = 0
    text_length = 0
    for letter in text:
        if letter.isalpha():
            text_length = text_length+1
    for i in range(0,NUMBER_OF_LETTERS_IN_ENGLISH_ALPHABET):
        occurences = text.count(chr(i+ASCII_OFFSET))
        kr = kr + (occurences*(occurences-1))
    return kr/(text_length*(text_length-1))

"""
    Calculates the difference in letter frequencies from text and
    the english language.

    text: Text to compare letter frequencies to.

    returns: A value representing how close the text is to english
    letter frequencies.
"""
def letter_frequencies(text):
    kr = 0
    for i in range(0,NUMBER_OF_LETTERS_IN_ENGLISH_ALPHABET):
        occurences = text.count(chr(i+ASCII_OFFSET))/len(text)
        kr = kr + (occurences-ENGLISH_LETTER_FREQUENCIES[i])**2
    return kr

"""
    Strips away everything except the alphabetical characters from text.

    text: String to be 'cleaned'

    returns: a String with only alphabetical characters.
"""
def string_clean(text):
    temp = ""
    for i in range(0,len(text)):
        if text[i].isalpha():
            temp = temp + text[i]
    return temp

"""
    Gets every n:th char of the string s starting at position start.
    
    s: A string to retrieve chars from
    start: Starting position
    n: How large steps to jump

    returns: A string containing every n:th character in text, at from start
"""
def get_nth_chars(text, start, n):
    value = ""
    for i in range(0,len(text)):
        if i%n == start:
            value = value+text[i]
    return value

"""
    Rotates text n steps to the right, wrapping it around itself.

    text: the text to rotate
    n: number of steps to rotate

    returns: text rotated n steps to the right.
"""
def rotate_right(text, n):
    cutting_point = len(text) - (n % len(text))
    return text[cutting_point:] + text[:cutting_point]

"""
    Guesses the keylength for the key used to encode text
    with a vigenere cipher. Guessing is done by using the
    Friedman test (also known as the kappa test)

    text: text encoded with a vigenere cipher

    returns: a guess of the keylength used to encode text
"""
def guess_keylength(text):
    kappas = []
    for i in range(4, 17):
        temp = rotate_right(text,i)
        occurrences = 0
        for j in range(len(text)):
            if temp[j] == text[j]:
                occurrences = occurrences+1
        kappas.append((0.0667-(float(occurrences)/len(text)))**2)
    smallest_diff = 0
    codeword_length = 0
    for i in range(0,13):
        current_diff = kappas[i]
        if smallest_diff == 0:
            smallest_diff = current_diff
        if current_diff < smallest_diff:
            codeword_length = 4 + i
            smallest_diff = current_diff
    return codeword_length
    
"""
    Encodes text using a caesar cipher, where the alphabet is shifted shift characters

    text: String to be encoded
    shift: How much to shift to encode with

    returns: A string encoded by shifting the alphabet shift letters.
"""
def caesar_shift(text, shift):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    # "from string import maketrans" is needed for version 3.1 of Python
    if sys.version_info < (3,2):
        from string import maketrans
    code = alphabet[shift:] + alphabet[:shift]
    trans = maketrans(alphabet, code)
    return text.translate(trans)

"""
    Discovers the correct key of length for decoding text

    text: String encoded using a vigenere cipher
    length: Length of the key to guess a keyword from

    returns: A string of length representing the key to decode text with.
"""
def guess_key(text, length):
    guess = ""
    for i in range(0, length):
        t = get_nth_chars(text, i, length)
        mini = -1
        shift = 0
        for j in range(0, NUMBER_OF_LETTERS_IN_ENGLISH_ALPHABET):
            # By doing the caesar shift backwards 
            tl = caesar_shift(t, -j)
            current = letter_frequencies(tl)
            if mini == -1:
                mini = current
            if current < mini:
                shift = j
                mini = current
        guess = guess+chr(ASCII_OFFSET+(shift))
    return guess



"""
    Decrypts text by using key, using the caesar_shift method.

    text: Text to be decrypted
    key: Key to use during decryption.

    returns: text decrypted using key.
"""
def decrypt_cipher(text, key):
    result = ""
    shift = 0
    for j in range(0,len(text)):
        # Basically do a reversed caesar shift on each character in the string
        # Shifting key each step
        result = result + caesar_shift(text[j], -((ord(key[j%len(key)])-ASCII_OFFSET)%NUMBER_OF_LETTERS_IN_ENGLISH_ALPHABET))
    return result

"""
    Attempts to decrypt text, by guessing a keylength and key. If the result is
    close to the english language letter frequencies, we assume the result is
    correct. Otherwise we try again with string length+-1

    text: A string encoded using Viegere cipher, in all lowercase.

    returns: The string decrypted to the english language, or an empty string if it failed.
"""
def viegenere_crack(text):
    # find key length need to implement guess keylength properly
    length = temp_length = guess_keylength(text)
    print(length)
    if length == 0:
        print("Couldn't guess a keylength")
        return ""
    # find key
    for i in range(0,3):
        key = guess_key(text, temp_length)
        decrypted = decrypt_cipher(text, key)
        cr = coincidence_rate(decrypted)
        if cr > 0.056 and cr < 0.08:
            return decrypted
        elif length == temp_length:
            temp_length = length+1
        else:
            temp_length = length-1
    return ""

# Testing function
def test_vigenere():
    cipher1 = "FVHQZPSOGSQQNICBSUJZDAVEFFCPEEUQYICUTLGLFWRRZRGDJPFMDRONCXROQROMGQBHWDBFRTPDHLIDUHWEVQGDWTZDXXLZSWAZDYRJEUAHHLGHRQLFODROMTRVXGZDXSQJHVTRWHVNMBDPDAPHYDQRLREQFDGEUJHPJFCHBLYWQIDQJHVLXDUSAQFWMPECIEDKGWIXUBFEDQHKIGQFLJTOOWMZZCIEAMFWMNGZDVCQOOXTYSVCDFSPJLUZVASUQKLLBDHRDYCUIZRHHRETOQRZFOGMLSBRWEUQWVLOSLWLGHRQLFWFEWXMUIAAFWIOUBRVOQFWSQMQLPTFOWIOQPXKRUBJMEUGSSDEWEPPFCLRDFFXGEFVHZPDWIMPDHRSAFWPMDQHKEEUGWVJFCUIOGQHXSQJHVTRWFEEUCQXTYSZLPZGHZPDOOTCADHVEUSVSQMGBWEQADVPQLDQTZSGMYESTYPZQHEDUALPLDCSXTABISCEDDGPADWMXUGDXTABDPDASAMDFGA"
    solution1 = "themodelcheckerperformsautomaticverificationofsafetyandboundedlivenesspropertiesittakesasinputanetworkoftimedautomataandaformulatheverifiercanalsobeusedinteractivelytoexamineseveralpropertiesofasystemincasetheverificationofaparticularrealtimesystemfailswhichhappensmoreoftenthannotadiagnostictraceisautomaticallyreportedinordertofacilitatedebuggingitispossibletoinstructtheverifiertooptimisethatistrytoreducetheverificationtimewhenseveralpropertiesofasystemareexaminedinsequenceasimilaroptionforspaceoptimisationalsoexistsx"

    cipher2 = "FFKASKWFRLFCEUEVIEQLTDFZSKAHNRLCRVOMEXHANFSYHDZFRJXCYEAEWHBRLWFPFCIFGFYRRJPVLBITALWBEUBAPVRPMOIIOLZOFPSRBKNYETHTJLTVKHHUTYTAXVFZGPNVLPBZNYERGZQVRZMOCEKKALJIOSELGKOSXXOZTVAVHVSKPPNYYFNPMKHRMFILVVGLPVRRVAORLCRRHFWEPOUKTYXXOVSKBVHZSSNACKWRLABVGIXHNHUVLACFNKALOCTZFHNVQLXZNZOEHMFZFVMOYLNZOLLJERGKYMEIRABZNXAVQCEUEVIEQLTDFPEJLHCUDVXWNYOLZONNIKAABVAZKVZFNVPOIJUWYLLJFFHSMXLRWSSSUKPOUKATMBUCLPBZCKAJEVQJTLILZZEULPFVNTXJLVPKHCYITYXTYEAJMOYPSKTYYUAKMOYTODIBNVRRGKNYEETAYRCYHABVR"
    solution2 = "fortytwoyelledloonquawlisthatallyouvegottoshowforsevenandahalfmillionyearsworkicheckeditverythoroughlysaidthecomputerandthatdefinitelyistheanswerithinktheproblemtobequitehonestwithyouisthatyouveneveractuallyknownwhatthequestionisbutitwasthegreatquestiontheultimatequestionoflifetheuniverseandeverythinghowledloonquawlyessaiddeepthoughtwiththeairofonewhosuffersfoolsgladlybutwhatactuallyisitaslowstupefiedsilencecreptoverthemenastheystaredatthecomputerandthenateachother"

    cipher3 = "IYMNTPOHYUHZRPKCXNDSGGHKSASGLBGHBQGJGSLRDLVQGHYWZTASKHVZQQETBZPQCMEEWKEGJIZVCDPUAQDLBNMUEIGBXWAVYKXKDWATPOJTNLBFJNGPPJLEBUKKWLQBBBFASNRLBAGRXAAZDLZJHTHKYFQIPKUINGQULBELKDRPAPRETFPUSBIXELHDRRVQFOGONEQDASAEZBEQTBUELYUNPKBUEIWHYCYABFASWIGUAUADSURCORNCDPQEVVVWULHHBQRAGHTHXVIVTQSMCNZTPOUTBBPUGLGRAGRONAZOVVXAALQBZOELHOUQAQPAGHWXGPB"
    solution3 = "greatwallsareprobablythreefeetthickweldedshutfromtheoutsideandcoveredwithbrickbynowdontgiveupjackokiwontwangletsjustchewourwayoutofherejustrememberwhatoldjackburtondoeswhentheearthquakesthepoisonarrowsfallfromtheskyandthepillarsofheavenshakeyeahjackburtonjustlooksthatbigoldstormrightintheeyeandsaysgivemeyourbestshoticantakeit"

    cipher4 = "cec27e03c51e1b18bc89e78003788ed0e87080f64da416cffda68f0d2cb3e9893ef5bcf00613b5dfdbb3827240a2d6f3ebc0ff1989fa2187c016722f53d141d2a7cd6f678118d6d425eecca627a4a85138180a6fbe74934ab51c31aa15811d06ca320390ee5781cd233ae7377a8d807caeeefe7267c4c6c9ca032124e1db8f361c3b4918a3931c119bcc3ac62ecbf4e09f7a95223d0bbe9f53415920db1ba3eb8f2bc85dc0e2e7a46d40b9c908777f59ea6197851569301788f38ea07b07e2245f92cc95a67a621726d5631c77fa637b4cd15daaa1a77de5e82e7ebcb73ca6803927adf975864c96b94e13aa542ad63be8f0e6ad1558aa4e7eaba0567751050ad858459ec4c0fbef5ce9aab20500fade"

    
    if not viegenere_crack(cipher1.lower()) == solution1:
        print("Test failed")
    if not viegenere_crack(cipher2.lower()) == solution2:
        print("Test failed")
    if not viegenere_crack(cipher3.lower()) == solution3:
        print("Test failed")
    else:
        print("All tests passed!")
    
def main():
    # Used for testing
    test_vigenere()
    encrypted = input("Please enter the vigenere encoded string, encoded from a english plaintext:\n")
    # Clean the input from non-alphabetical characters
    encrypted = string_clean(encrypted)
    tick = time.time()
    p = viegenere_crack(encrypted.lower())
    if p == "":
        print("Couldn't break the cipher.")
    print("It took", time.time()-tick, "seconds to run the cracking algorithm.")
    print("Resulting plaintext:", p)

main()
