
JFLAGS = -cp
JAVAC=javac
JAR1 = "commons-cli-1.4.jar"
.SUFFIXES: .java .class
sources = $(wildcard *.java)
classes = $(sources:.java=.class)

myProgram: $(classes)

%.class: %.java
	$(JAVAC) $(JFLAGS) $(JAR1) Dsa.java Tester.java
	mkdir dwhipple
	cp *.class dwhipple

# do a make run initiall with just a message.txt file in current working directory
# This will create signature, private key, public key
run:
	java -classpath .:commons-cli-1.4.jar dwhipple.Tester -privatekey privkey.txt -publickey pubkey.txt -sign sig.txt -message message.txt -verbose

# do a "make verify" next, this will load the public key and the signature and verify the message.txt file.
#
verify:
	java -classpath .:commons-cli-1.4.jar dwhipple.Tester -privatekey privkey.txt -publickey pubkey.txt -sign sig.txt -message message.txt -verbose -verify

help:
	clear
	@echo "This will properly run my Tester program, correctly setting CLASSPATH"
	@echo
	java -classpath .:commons-cli-1.4.jar dwhipple.Tester
	exit 0
security:
	clear
	@echo "This will print all supported security algorithms in your version of JAVA"
	@echo
	java -classpath .:commons-cli-1.4.jar dwhipple.Tester -supportedalgorithms -verbose
genkeys:
	clear
	@echo "This will run the program and just generate a public/private key pair, writing them to publickey.txt and privatekey.txt respectively"
	@echo
	java -classpath .:commons-cli-1.4.jar dwhipple.Tester -genkeysonly -verbose -publickey publickey.txt -privatekey privatekey.txt
fail:
	cp differentmessage.txt message.txt
	java -classpath .:commons-cli-1.4.jar dwhipple.Tester -privatekey privkey.txt -publickey pubkey.txt -sign sig.txt -message message.txt -verbose -verify
	cp oldmessage.txt message.txt

clean:
	rm -f sig.txt
	rm -f privkey.txt
	rm -f pubkey.txt
	rm -f publickey.txt
	rm -f privatekey.txt
	rm -f *.class
	rm -f dwhipple/*.class
	rmdir dwhipple
