#pragma once

template <bool isServer> class ExtensionsNegotiator {
  private:
    int options;

  public:
    ExtensionsNegotiator(int wantedOptions);
    std::string generateOffer();
    void readOffer(std::string offer);
    int getNegotiatedOptions();
};
