# HyperLogLog++

A pure-Rust implementation of [HyperLogLog++](https://research.google/pubs/pub40671/), based on [Google's Java source code](https://github.com/google/zetasketch).

Example usage:
```
        use hyperloglogplusplus::HyperLogLogPlusPlus;

        fn hash<T: std::hash::Hash>(t: T) -> u64 {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            t.hash(&mut hasher);
            std::hash::Hasher::finish(&hasher)
        }

        let mut hllpp = HyperLogLogPlusPlus::new();
        hllpp.add_hash(hash(String::from("apple")));
        hllpp.add_hash(hash(String::from("banana")));
        hllpp.add_hash(hash(String::from("banana")));
        assert_eq!(hllpp.get_estimate(), 2);

        let mut hllpp2 = HyperLogLogPlusPlus::new();
        hllpp2.add_hash(hash(String::from("orange")));
        hllpp2.add_hash(hash(String::from("banana")));
        assert_eq!(hllpp2.get_estimate(), 2);

        hllpp2.merge(&hllpp);
        assert_eq!(hllpp2.get_estimate(), 3);
```
