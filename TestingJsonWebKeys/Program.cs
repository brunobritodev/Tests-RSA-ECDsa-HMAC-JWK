namespace TestingJsonWebKeys
{
    class Program
    {

        static void Main(string[] args)
        {
            // HMAC using SHA-256
            HmacExample.Run();

            // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
            RsaExample.Run();

            // ECDSA using P-256 and SHA-256
            ECDsaExample.Run();
        }

    }
}
