namespace CyberSOC.Shared.Common
{
    /// <summary>
    /// Explicit success/failure wrapper. Used as the return type for almost every
    /// Application-layer handler so failures are part of the method signature,
    /// not hidden behind thrown exceptions.
    /// </summary>
    public class Result
    {
        public bool IsSuccess { get; }
        public string? Error { get; }
        public string[] Errors { get; }

        protected Result(bool isSuccess, string[] errors)
        {
            IsSuccess = isSuccess;
            Errors = errors;
            Error = errors.Length > 0 ? errors[0] : null;
        }

        public static Result Success() => new(true, Array.Empty<string>());
        public static Result Failure(string error) => new(false, new[] { error });
        public static Result Failure(IEnumerable<string> errors) => new(false, errors.ToArray());

        public static Result<T> Success<T>(T value) => Result<T>.Success(value);
        public static Result<T> Failure<T>(string error) => Result<T>.Failure(error);
    }

    public sealed class Result<T> : Result
    {
        public T? Value { get; }

        private Result(bool isSuccess, T? value, string[] errors) : base(isSuccess, errors)
        {
            Value = value;
        }

        public static Result<T> Success(T value) => new(true, value, Array.Empty<string>());
        public new static Result<T> Failure(string error) => new(false, default, new[] { error });
        public new static Result<T> Failure(IEnumerable<string> errors) => new(false, default, errors.ToArray());
    }

}
