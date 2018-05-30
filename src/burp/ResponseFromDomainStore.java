package burp;

//TODO: This class will store the last response + timestamp to each domain.
// this will allow AutoRepeater to replace values in Requests based on previous responses from domains
// This will be its own HTTPListener to keep track of all requests, not just the one's AutoRepeater sends
// The Data store should be something along the lines of a Map of some storage object which holds the timestamp + RequestResponse
// and the key being the domain. It might make sense to use the full path instead of just the URL. 
public class ResponseFromDomainStore {

}
