export function RawJsonTab({ value }: { value: unknown }) {
  return (
    <div className="scroll-x">
      <pre className="raw-json">{JSON.stringify(value, null, 2)}</pre>
    </div>
  );
}
