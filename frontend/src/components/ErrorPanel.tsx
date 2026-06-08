export function ErrorPanel({ title, message }: { title: string; message: string }) {
  return (
    <div className="error-panel" role="alert">
      <strong>{title}</strong>
      <span>{message}</span>
    </div>
  );
}
