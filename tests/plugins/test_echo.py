from foghorn.plugins.resolve.base import BasePlugin


class EchoPlugin(BasePlugin):
    def handle(self, qname, qtype, qclass, rdata):
        """
        Return a TXT record containing the qname and qtype
        """
        return [("TXT", f"{qname}\x00{qtype}")]


def test_echo_plugin():
    plugin = EchoPlugin()
    result = plugin.handle("example.com", "A", "IN", [])
    assert result == [("TXT", "example.com\x00A")]
    print("Test passed!")
