import threading
from helpers.FloydsHelpers import FloydsHelpers
# Jav
# a stdlib imports
from helpers.FloydsHelpers import FloydsHelpers
from java.lang import Thread
from java.lang import IllegalStateException
# python stdlib imports
import time  # detect timeouts and sleep for Threads
import threading  # to make stuff thread safe

class BurpCollaborator:
    # The actual size returned by a BurpCollaboratorClientContext starts with 31 and quickly goes up to 32
    # I haven't seen more than that in practice. According to the Burp guys, 33 seems to be a reasonable choice as:
    # 31 chars up to 15 IDs, 32 up to 255, then 33 up to 4095, then 34 up to 65536, etc.
    # As we currently do around 2000 files, where only max. half of them have Collaborator payloads, 33 is fine.
    # Let's be on the safe side and do 34
    FIXED_PAYLOAD_SIZE = 34
    # *must* be an uppercase letter
    PADDING_CHAR = "N"

    # A IBurpCollaboratorClientContext object that also knows if the
    # collaborator is configured with a DNS name or as an IP
    # Also creates fixed size payloads, always length FIXED_PAYLOAD_SIZE + 1 + len(server location)
    def __init__(self, callbacks):
        self.is_ip_collaborator = False
        self.is_available = False
        self.burp_colab = callbacks.createBurpCollaboratorClientContext()
        if self.burp_colab:
            # IP Form:  192.168.0.1/payload
            # DNS Form: payload.burpcollaborator.net
            try:
                self.is_ip_collaborator = '/' in FloydsHelpers.u2s(callbacks.createBurpCollaboratorClientContext().generatePayload(True))
                self.server_location = FloydsHelpers.u2s(self.burp_colab.getCollaboratorServerLocation())
                self.is_available = True
            except IllegalStateException:
                # happens when Option "Don't use Burp Collaborator" is chosen in project options
                self.burp_colab = None

    def fetchAllCollaboratorInteractions(self):
        return self.burp_colab.fetchAllCollaboratorInteractions()

    def getCollaboratorServerLocation(self):
        return self.burp_colab.getCollaboratorServerLocation()

    def generate_payload(self, includeCollaboratorServerLocation):
        payload = FloydsHelpers.u2s(self.burp_colab.generatePayload(includeCollaboratorServerLocation))
        return self.add_padding(payload)

    def add_padding(self, payload):
        current_length = len(payload)
        if self.server_location in payload:
            current_length -= len(self.server_location)
            # The . or /
            current_length -= 1
        padding = BurpCollaborator.FIXED_PAYLOAD_SIZE - current_length
        if padding < 0:
            print("Warning: Something is wrong with fixed size payload calculation in BurpCollaborator class. " \
                  "Did you reconfigure the Collaborator server?")
        elif padding == 0:
            pass  # No need to do padding
        else:  # 1 and above
            if self.is_ip_collaborator:
                # IP Form:  192.168.0.1/payload
                # We create: 192.168.0.1/payload/NNNNNNNNNN
                payload = payload + "/" + (padding - 1) * BurpCollaborator.PADDING_CHAR
            else:
                # DNS Form: payload.burpcollaborator.net
                # We create: NNNpayload.burpcollaborator.net
                # Do *not* use a dot between NNN and payload as the
                # Collaborator TLS certificate is not valid for such a domain
                payload = padding * BurpCollaborator.PADDING_CHAR + payload
        return payload

    def remove_padding(self, payload):
        if self.is_ip_collaborator:
            # IP Form:  192.168.0.1/payload
            while payload.endswith(BurpCollaborator.PADDING_CHAR):
                payload = payload[:-1]
            if payload.endswith("/"):
                # Remove / as well:
                payload = payload[:-1]
        else:
            # DNS Form: payload.burpcollaborator.net
            # This works because Burp Collaborator payload never contains upper case characters
            while payload.startswith(BurpCollaborator.PADDING_CHAR):
                payload = payload[1:]
        return payload

    def get_dummy_payload(self):
        if self.is_ip_collaborator:
            return self.server_location + "/" + BurpCollaborator.FIXED_PAYLOAD_SIZE * BurpCollaborator.PADDING_CHAR
        else:
            return BurpCollaborator.FIXED_PAYLOAD_SIZE * BurpCollaborator.PADDING_CHAR + "." + self.server_location


class CollaboratorMonitorThread(Thread):

    NAME = "UploadScannerExtensionMonitorThread"

    def __init__(self, burp_extender):
        Thread.__init__(self)
        self.burp_extender = burp_extender
        self.colabs = []
        self.stop = False
        self.paused = False
        self.lock = threading.Lock()
        self.setName(CollaboratorMonitorThread.NAME)
        self.saved_interactions_for_later = {}
        self.print_message_counter = 0

    def add_or_update(self, burp_colab, colab_tests):
        # Create a dictionary that maps colab_url to the colab_test objects:
        colab_dict = {}
        for colab_test in colab_tests:
            # print(colab_test.colab_url)
            colab_dict[colab_test.colab_url] = colab_test
        with self.lock:
            # Check if we already know that burp_colab instance
            for index, instance_dict_tuple in enumerate(self.colabs):
                if burp_colab is instance_dict_tuple[0]:
                    # If yes, replace that slot
                    self.colabs[index] = (burp_colab, colab_dict)
                    break
            else:
                # If not, add a new one
                self.colabs.append((burp_colab, colab_dict))

    def extensionUnloaded(self):
        # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
        # One idea was on extension unload we just "pause" the functionality of the thread...
        # self.paused = True
        self.stop = True

    def stop(self):
        with self.lock:
            self.stop = True

    def pause(self):
        with self.lock:
            self.paused = True
            self.burp_extender = None

    def resume(self, extension):
        with self.lock:
            self.paused = False
            self.burp_extender = extension

    def run(self):
        while not self.stop:
            if not self.paused:
                with self.lock:
                    # print("Checking interactions...")
                    self.check_interactions()
            for _ in range(0, 8):
                if self.stop:
                    return
                time.sleep(2)

    def check_interactions(self):
        for burp_colab, colab_dict in self.colabs:
            # Create a dictionary that maps colab_url to the interaction objects:
            all_interactions = burp_colab.fetchAllCollaboratorInteractions()
            interactions_dict = {}
            server = FloydsHelpers.u2s(burp_colab.getCollaboratorServerLocation())
            for interaction in all_interactions:
                interaction_id = FloydsHelpers.u2s(interaction.getProperty("interaction_id"))
                interaction_id = burp_colab.add_padding(interaction_id)
                if burp_colab.is_ip_collaborator:
                    found_colab_url = "{}/{}".format(server, interaction_id)
                else:
                    found_colab_url = "{}.{}".format(interaction_id, server)
                # print(found_colab_url)
                interactions_dict.setdefault(found_colab_url, []).append(interaction)
            # Also check the saved ones
            interactions_dict.update(self.saved_interactions_for_later)
            self.saved_interactions_for_later = {}
            # Loop through interactions and add issues
            for found_colab_url in interactions_dict:
                # print("colab_dict:", repr(colab_dict))
                # print("found_colab_url:", repr(found_colab_url))
                try:
                    colab_test = colab_dict[found_colab_url]
                except KeyError:
                    self.saved_interactions_for_later[found_colab_url] = interactions_dict[found_colab_url]
                else:
                    interactions = interactions_dict[found_colab_url]
                    issue = colab_test.issue.create_copy()
                    issue.detail += self._get_interactions_as_str(interactions)
                    issue.setUrl(self.burp_extender._helpers.analyzeRequest(colab_test.urr.upload_rr).getUrl())
                    issue.httpMessagesPy.append(colab_test.urr.upload_rr)
                    if colab_test.urr.preflight_rr:
                        issue.httpMessagesPy.append(colab_test.urr.preflight_rr)
                    if colab_test.urr.download_rr:
                        issue.httpMessagesPy.append(colab_test.urr.download_rr)
                    self.burp_extender._add_scan_issue(issue)
            if self.saved_interactions_for_later:
                if self.print_message_counter % 10 == 0:
                    print("Found Collaborator interactions where we didn't get the issue details yet, saving for later... " \
                        "This message shouldn't be printed anymore after all scans are finished.")  #, repr(self.saved_interactions_for_later.keys())
                self.print_message_counter += 1

    def _get_interactions_as_str(self, interactions):
        desc = ""
        for index, interaction in enumerate(interactions):
            t = FloydsHelpers.u2s(interaction.getProperty("type"))
            desc += "<br><b>Interaction " + str(index) + "</b><br>"
            desc += " ".join(["Type: ", FloydsHelpers.u2s(interaction.getProperty("type")),
                                  "<br>Client IP: ", FloydsHelpers.u2s(interaction.getProperty("client_ip")),
                                  "<br>Timestamp: ", FloydsHelpers.u2s(interaction.getProperty("time_stamp")), "<br>"])
            if t == "DNS":
                desc += "<br>DNS query type: " + FloydsHelpers.u2s(interaction.getProperty("query_type"))
                desc += "<br>RAW query: " + FloydsHelpers.jb2ps(
                    self.burp_extender._helpers.base64Decode(interaction.getProperty("raw_query")))
                desc += "<br>"
            elif t == "HTTP":
                desc += "<br>Protocol: " + FloydsHelpers.u2s(interaction.getProperty("protocol")) + "<br>"
                desc += "<br>RAW " + FloydsHelpers.u2s(interaction.getProperty("protocol")) + " request:<br>" + FloydsHelpers.jb2ps(
                    self.burp_extender._helpers.base64Decode(interaction.getProperty("request"))).replace("\n", "<br>")
                desc += "<br>RAW " + FloydsHelpers.u2s(interaction.getProperty("protocol")) + " response:<br>" + FloydsHelpers.jb2ps(
                    self.burp_extender._helpers.base64Decode(interaction.getProperty("response"))).replace("\n", "<br>")
                desc += "<br>"
        desc += "<br>"
        return desc